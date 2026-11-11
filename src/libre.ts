/**
 * FreeStyle Libre glucose via LibreLinkUp (follower account), read-only.
 *
 * LibreLinkUp only exposes the last ~12 hours, so a cron job (every 5 minutes,
 * see wrangler.jsonc "triggers") collects new readings into KV, one key per
 * local calendar day. The MCP tools read from that history.
 *
 * Secrets (Cloudflare → Settings → Variables and secrets):
 *   LIBRE_EMAIL     follower account e-mail (required)
 *   LIBRE_PASSWORD  follower account password (required)
 *   LIBRE_REGION    optional, e.g. "ap", "eu", "us"; normally detected automatically
 *   LIBRE_VERSION   optional app version header if LibreLinkUp starts rejecting the default
 *   LIBRE_PATIENT_ID optional, only if the follower account follows more than one person
 *
 * Unofficial interface: it may change or stop working at any time. Not a medical device.
 */
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { resolveDateRange, addDays } from "./dates";

type Kv = {
	get(key: string): Promise<string | null>;
	put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
	delete(key: string): Promise<void>;
};
type LibreEnv = {
	OAUTH_KV: Kv;
	TIMEZONE?: string;
	LIBRE_EMAIL?: string;
	LIBRE_PASSWORD?: string;
	LIBRE_REGION?: string;
	LIBRE_VERSION?: string;
	LIBRE_PATIENT_ID?: string;
};

const K_AUTH = "glu:auth";
const K_LATEST = "glu:latest";
const K_STATUS = "glu:status";
const kDay = (day: string) => `glu:day:${day}`;
const KEEP_SECONDS = 400 * 86400;
const DEFAULT_VERSION = "4.16.0";

class LibreError extends Error {
	constructor(message: string, public code: string) {
		super(message);
	}
}

function baseUrl(region?: string | null): string {
	const r = (region || "").trim().toLowerCase();
	return r ? `https://api-${r}.libreview.io` : "https://api.libreview.io";
}

function headers(env: LibreEnv, extra: Record<string, string> = {}): Record<string, string> {
	return {
		"content-type": "application/json",
		accept: "application/json",
		"cache-control": "no-cache",
		product: "llu.android",
		version: (env.LIBRE_VERSION || DEFAULT_VERSION).trim(),
		...extra,
	};
}

async function sha256Hex(text: string): Promise<string> {
	const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface Auth {
	token: string;
	expires: number; // unix seconds
	accountId: string; // sha256 of user id
	base: string;
}

async function login(env: LibreEnv): Promise<Auth> {
	if (!env.LIBRE_EMAIL || !env.LIBRE_PASSWORD) {
		throw new LibreError("LIBRE_EMAIL and LIBRE_PASSWORD are not set in Cloudflare.", "not_configured");
	}
	let base = baseUrl(env.LIBRE_REGION);
	for (let attempt = 0; attempt < 3; attempt++) {
		const res = await fetch(`${base}/llu/auth/login`, {
			method: "POST",
			headers: headers(env),
			body: JSON.stringify({ email: env.LIBRE_EMAIL.trim(), password: env.LIBRE_PASSWORD }),
		});
		const text = await res.text();
		let json: any = null;
		try {
			json = JSON.parse(text);
		} catch {
			/* not JSON */
		}
		if (!res.ok || !json) {
			throw new LibreError(`LibreLinkUp login failed (HTTP ${res.status}).`, res.status === 403 || res.status === 430 ? "blocked" : "login_failed");
		}
		const data = json.data ?? {};
		if (data.redirect && data.region) {
			base = baseUrl(String(data.region));
			continue;
		}
		if (json.status === 2) throw new LibreError("LibreLinkUp rejected the e-mail or password.", "bad_credentials");
		if (json.status === 4 || data.step) {
			throw new LibreError(
				"LibreLinkUp wants you to accept updated terms. Open the LibreLinkUp app, sign in with the follower account and accept them.",
				"terms",
			);
		}
		if (json.status === 920) {
			throw new LibreError("LibreLinkUp says the app version is too old. Set the LIBRE_VERSION secret to a newer version (e.g. 4.17.0).", "version");
		}
		const token = data.authTicket?.token;
		const userId = data.user?.id;
		if (!token || !userId) throw new LibreError(`Unexpected LibreLinkUp login reply (status ${json.status}).`, "login_failed");
		return {
			token,
			expires: Number(data.authTicket?.expires) || Math.floor(Date.now() / 1000) + 3600,
			accountId: await sha256Hex(String(userId)),
			base,
		};
	}
	throw new LibreError("LibreLinkUp kept redirecting between regions. Set LIBRE_REGION.", "login_failed");
}

async function getAuth(env: LibreEnv, force = false): Promise<Auth> {
	if (!force) {
		const raw = await env.OAUTH_KV.get(K_AUTH);
		if (raw) {
			try {
				const a = JSON.parse(raw) as Auth;
				if (a.token && a.expires - 300 > Date.now() / 1000) return a;
			} catch {
				/* re-login */
			}
		}
	}
	const a = await login(env);
	await env.OAUTH_KV.put(K_AUTH, JSON.stringify(a), { expirationTtl: Math.max(600, a.expires - Math.floor(Date.now() / 1000)) });
	return a;
}

async function llu(env: LibreEnv, path: string): Promise<any> {
	for (let attempt = 0; attempt < 2; attempt++) {
		const a = await getAuth(env, attempt > 0);
		const res = await fetch(`${a.base}${path}`, {
			headers: headers(env, { authorization: `Bearer ${a.token}`, "account-id": a.accountId }),
		});
		if (res.status === 401 && attempt === 0) {
			await env.OAUTH_KV.delete(K_AUTH);
			continue;
		}
		if (!res.ok) throw new LibreError(`LibreLinkUp request failed (HTTP ${res.status}).`, res.status === 429 ? "rate_limited" : "request_failed");
		const json: any = await res.json();
		if (json?.status && json.status !== 0) throw new LibreError(`LibreLinkUp returned status ${json.status}.`, "request_failed");
		return json?.data;
	}
	throw new LibreError("LibreLinkUp sign-in expired and could not be renewed.", "login_failed");
}

/** "11/10/2026 1:45:00 AM" (UTC, LibreLinkUp FactoryTimestamp) → epoch ms. */
function parseFactoryTs(s: unknown): number | null {
	const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)?$/i.exec(String(s ?? "").trim());
	if (!m) return null;
	let h = Number(m[4]);
	const ap = (m[7] || "").toUpperCase();
	if (ap === "PM" && h < 12) h += 12;
	if (ap === "AM" && h === 12) h = 0;
	return Date.UTC(Number(m[3]), Number(m[1]) - 1, Number(m[2]), h, Number(m[5]), Number(m[6]));
}

function localParts(ms: number, timeZone: string): { day: string; min: number } {
	const parts = new Intl.DateTimeFormat("en-CA", {
		timeZone,
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		hourCycle: "h23",
	}).formatToParts(new Date(ms));
	const p: Record<string, string> = {};
	for (const x of parts) p[x.type] = x.value;
	return { day: `${p.year}-${p.month}-${p.day}`, min: (Number(p.hour) % 24) * 60 + Number(p.minute) };
}

const TREND: Record<number, string> = { 1: "falling quickly", 2: "falling", 3: "stable", 4: "rising", 5: "rising quickly" };

interface DayDoc {
	t: number[];
	g: number[];
}

async function readDay(env: LibreEnv, day: string): Promise<DayDoc> {
	const raw = await env.OAUTH_KV.get(kDay(day));
	if (!raw) return { t: [], g: [] };
	try {
		const d = JSON.parse(raw);
		return { t: Array.isArray(d.t) ? d.t : [], g: Array.isArray(d.g) ? d.g : [] };
	} catch {
		return { t: [], g: [] };
	}
}

/** Collect new readings into KV. Safe to call often; only writes days that changed. */
export async function collectGlucose(env: LibreEnv): Promise<{ added: number }> {
	const timeZone = env.TIMEZONE || "UTC";
	try {
		let pid = (env.LIBRE_PATIENT_ID || "").trim();
		if (!pid) {
			const conns = await llu(env, "/llu/connections");
			if (!Array.isArray(conns) || !conns.length) {
				throw new LibreError("The follower account doesn't follow anyone yet. Accept the invitation in the LibreLinkUp app.", "no_connection");
			}
			pid = String(conns[0].patientId);
		}
		const data = await llu(env, `/llu/connections/${encodeURIComponent(pid)}/graph`);
		const points: { ms: number; v: number }[] = [];
		for (const r of Array.isArray(data?.graphData) ? data.graphData : []) {
			const ms = parseFactoryTs(r.FactoryTimestamp);
			const v = Number(r.ValueInMgPerDl);
			if (ms && Number.isFinite(v) && v > 0) points.push({ ms, v });
		}
		const cur = data?.connection?.glucoseMeasurement;
		const curMs = cur ? parseFactoryTs(cur.FactoryTimestamp) : null;
		if (cur && curMs && Number.isFinite(Number(cur.ValueInMgPerDl))) {
			points.push({ ms: curMs, v: Number(cur.ValueInMgPerDl) });
			const lp = localParts(curMs, timeZone);
			await env.OAUTH_KV.put(
				K_LATEST,
				JSON.stringify({
					mgdl: Number(cur.ValueInMgPerDl),
					trend: TREND[Number(cur.TrendArrow)] ?? null,
					measured_at_utc: new Date(curMs).toISOString(),
					day: lp.day,
					time: `${String(Math.floor(lp.min / 60)).padStart(2, "0")}:${String(lp.min % 60).padStart(2, "0")}`,
				}),
			);
		}
		// Group by local day and merge.
		const byDay = new Map<string, Map<number, number>>();
		for (const p of points) {
			const lp = localParts(p.ms, timeZone);
			if (!byDay.has(lp.day)) byDay.set(lp.day, new Map());
			byDay.get(lp.day)!.set(lp.min, Math.round(p.v));
		}
		let added = 0;
		for (const [day, fresh] of byDay) {
			const doc = await readDay(env, day);
			const merged = new Map<number, number>();
			doc.t.forEach((t, i) => merged.set(t, doc.g[i]));
			let changed = false;
			for (const [t, g] of fresh) {
				if (merged.get(t) !== g) {
					if (!merged.has(t)) added++;
					merged.set(t, g);
					changed = true;
				}
			}
			if (changed) {
				const sorted = [...merged.entries()].sort((a, b) => a[0] - b[0]);
				await env.OAUTH_KV.put(kDay(day), JSON.stringify({ t: sorted.map((x) => x[0]), g: sorted.map((x) => x[1]) }), {
					expirationTtl: KEEP_SECONDS,
				});
			}
		}
		await env.OAUTH_KV.put(K_STATUS, JSON.stringify({ ok: true, at: new Date().toISOString(), added }));
		return { added };
	} catch (err) {
		const e = err instanceof LibreError ? err : new LibreError("Unexpected error while reading LibreLinkUp.", "unexpected");
		console.error(`libre collect: ${e.code}`);
		await env.OAUTH_KV.put(K_STATUS, JSON.stringify({ ok: false, at: new Date().toISOString(), code: e.code, message: e.message }));
		throw e;
	}
}

async function status(env: LibreEnv): Promise<unknown> {
	const raw = await env.OAUTH_KV.get(K_STATUS);
	try {
		return raw ? JSON.parse(raw) : { ok: false, message: "The collector hasn't run yet." };
	} catch {
		return null;
	}
}

const text = (body: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(body) }] });
const fail = (message: string) => ({ content: [{ type: "text" as const, text: message }], isError: true });
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;
const dateParam = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Use YYYY-MM-DD").optional();

export interface GlucoseDeps {
	timeZone: string;
	env: LibreEnv;
	/** Throws if the caller is not the allowed user. */
	checkAuth(): void;
	checkRateLimit(): Promise<void>;
}

export function registerGlucoseTools(server: McpServer, deps: GlucoseDeps): void {
	const tz = deps.timeZone;

	server.registerTool(
		"get_glucose_current",
		{
			title: "Current glucose",
			description:
				"The latest FreeStyle Libre glucose reading (mg/dL) with trend, read through LibreLinkUp, plus the collector's status. Not a medical device; for lows and treatment decisions rely on the Libre app and its alarms.",
			inputSchema: z.object({}),
			annotations: { title: "Current glucose", ...READ_ONLY },
		},
		async () => {
			try {
				deps.checkAuth();
				await deps.checkRateLimit();
				try {
					await collectGlucose(deps.env);
				} catch {
					/* fall back to the last stored reading; status explains */
				}
				const latest = await deps.env.OAUTH_KV.get(K_LATEST);
				return text({ timezone: tz, latest: latest ? JSON.parse(latest) : null, collector: await status(deps.env) });
			} catch (err) {
				return fail(err instanceof Error ? err.message : "Unexpected server error.");
			}
		},
	);

	server.registerTool(
		"get_glucose_history",
		{
			title: "Glucose history",
			description: `FreeStyle Libre glucose readings collected from LibreLinkUp, per calendar day in ${tz}: "t" is minutes after local midnight, "g" the glucose in mg/dL at that minute (roughly every 5-15 minutes). History starts when the collector was set up. Defaults to the last 7 days; max 90 days per call.`,
			inputSchema: z.object({
				start_date: dateParam.describe(`First day (YYYY-MM-DD, ${tz}). Defaults to 6 days before end_date.`),
				end_date: dateParam.describe(`Last day (YYYY-MM-DD, ${tz}). Defaults to today.`),
			}),
			annotations: { title: "Glucose history", ...READ_ONLY },
		},
		async ({ start_date, end_date }) => {
			try {
				deps.checkAuth();
				await deps.checkRateLimit();
				const range = resolveDateRange(start_date, end_date, tz);
				const data: { day: string; t: number[]; g: number[] }[] = [];
				for (let d = range.start; d <= range.end; d = addDays(d, 1)) {
					const doc = await readDay(deps.env, d);
					if (doc.t.length) data.push({ day: d, ...doc });
				}
				return text({ start_date: range.start, end_date: range.end, timezone: tz, unit: "mg/dL", count: data.length, data, collector: await status(deps.env) });
			} catch (err) {
				return fail(err instanceof Error ? err.message : "Unexpected server error.");
			}
		},
	);
}
