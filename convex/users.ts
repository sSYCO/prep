import { internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ---- internal: only auth.ts (server side) can call these ----
export const getByEmail = internalQuery({
  args: { email: v.string() },
  handler: async (ctx, { email }) =>
    await ctx.db.query("users").withIndex("by_email", (q) => q.eq("email", email)).unique(),
});

export const create = internalMutation({
  args: { name: v.string(), email: v.string(), passwordHash: v.string(), salt: v.string() },
  handler: async (ctx, a) => {
    const existing = await ctx.db
      .query("users").withIndex("by_email", (q) => q.eq("email", a.email)).unique();
    if (existing) return null; // email already registered
    return await ctx.db.insert("users", { ...a, createdAt: Date.now() });
  },
});

export const createSession = internalMutation({
  args: { userId: v.id("users"), token: v.string() },
  handler: async (ctx, { userId, token }) => {
    const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
    await ctx.db.insert("sessions", { userId, token, expiresAt: Date.now() + THIRTY_DAYS });
  },
});

// ---- public: called from the browser ----
export const me = query({
  args: { token: v.string() },
  handler: async (ctx, { token }) => {
    const s = await ctx.db.query("sessions").withIndex("by_token", (q) => q.eq("token", token)).unique();
    if (!s || s.expiresAt < Date.now()) return null;
    const u = await ctx.db.get(s.userId);
    return u ? { name: u.name, email: u.email } : null;
  },
});

export const logout = mutation({
  args: { token: v.string() },
  handler: async (ctx, { token }) => {
    const s = await ctx.db.query("sessions").withIndex("by_token", (q) => q.eq("token", token)).unique();
    if (s) await ctx.db.delete(s._id);
  },
});