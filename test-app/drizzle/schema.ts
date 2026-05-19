import { pgTable, uuid, text, boolean, integer, timestamp, jsonb } from "drizzle-orm/pg-core"

// VULNERABILITY: isAdmin field directly exposed, no soft delete
// Scanner: drizzle_schema_analyzer (#30)

export const profiles = pgTable("profiles", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").unique().notNull(),
  displayName: text("display_name"),
  role: text("role").default("user"),
  isAdmin: boolean("is_admin").default(false),  // Sensitive: mass assignment target
  avatarUrl: text("avatar_url"),
  createdAt: timestamp("created_at").defaultNow(),
})

export const tasks = pgTable("tasks", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").references(() => profiles.id),
  title: text("title").notNull(),
  description: text("description"),
  status: text("status").default("pending"),
  priority: integer("priority").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
})

export const credits = pgTable("credits", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").references(() => profiles.id),
  balance: integer("balance").default(100),
  lastRedeemedAt: timestamp("last_redeemed_at"),
})

export const settings = pgTable("settings", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").references(() => profiles.id),
  preferences: jsonb("preferences").default({}),
  notificationsEnabled: boolean("notifications_enabled").default(true),
})
