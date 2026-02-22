import {
  clerkMiddleware,
  createRouteMatcher,
  clerkClient,
} from "@clerk/nextjs/server"
import { NextResponse } from "next/server"

const isPublicRoute = createRouteMatcher([
  "/",
  "/api/webhook/register",
  "/sign-up(.*)",
  "/sign-in(.*)",
])

export default clerkMiddleware(async (auth, req) => {
  const { userId } = await auth()

  // Handle unauth users trying to access protected routes
  if (!userId && !isPublicRoute(req)) {
    return NextResponse.redirect(new URL("/sign-in", req.url))
  }

  if (userId) {
    try {
      const client = await clerkClient()
      const user = await client.users.getUser(userId)
      const role = user.publicMetadata.role as string | undefined

      // Admin role redirection
      if (role === "admin" && req.nextUrl.pathname === "/dashboard") {
        return NextResponse.redirect(new URL("/admin/dashboard", req.url))
      }

      // Preventing non-admin users from accessing admin routes
      if (role !== "admin" && req.nextUrl.pathname.startsWith("/admin")) {
        return NextResponse.redirect(new URL("/dashboard", req.url))
      }

      // Redirect authenticated users away from sign-in or sign-up
      if (
        isPublicRoute(req) &&
        req.nextUrl.pathname !== "/" &&
        !req.nextUrl.pathname.startsWith("/api")
      ) {
        return NextResponse.redirect(
          new URL(
            role === "admin" ? "/admin/dashboard" : "/dashboard",
            req.url,
          ),
        )
      }
    } catch (error) {
      console.log(error)
      return NextResponse.redirect(new URL("/error", req.url))
    }
  }
})

export const config = {
  matcher: [
    // Skip Next.js internals and all static files, unless found in search params
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    // Always run for API routes
    "/(api|trpc)(.*)",
  ],
}
