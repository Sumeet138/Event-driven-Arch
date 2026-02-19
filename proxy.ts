import { authMiddleware, clerkClient } from "@clerk/nextjs/server"
import { NextRequest, NextResponse } from "next/server"
import { log } from "node:console"

const publicRoute = ["/", "/api/webhook/register", "sign-up", "sign-in"]

export default authMiddleware({
  publicRoute,
  async afterAuth(auth, req) {
    //handle unauth users trying to acces procted users
    if (!auth.userId && !publicRoute.includes(req.nextUrl.pathname)) {
      return NextResponse.redirect(new URL("/sign-in", req.url))
    }
    if (auth.userId) {
      try {
        const client = await clerkClient()
        const users = await client.users.getUser(auth.userId)
        const role = users.publicMetadata.role as String | undefined

        //admin role redirection
        if (role === "admin" && req.nextUrl.pathname === "/dashboard") {
          return NextResponse.redirect(new URL("admin/dashboard", req.url))
        }

        //preventing non admin user to acces admin routes
        if (role != "admin" && req.nextUrl.pathname.startsWith("/admin")) {
          return NextResponse.redirect(new URL("/dashboard", req.url))
        }

        //redirect auth user from sign in or sign up
        if (publicRoute.includes(req.nextUrl.pathname)) {
          return NextResponse.redirect(
            new URL(
              role === "admin" ? "/admin/dashboard" : "/dashboard",
              req.url,
            ),
          )
        }
      } catch (error) {
        console.log(error)
        return NextResponse.redirect(new URL("/error", req.URL))
      }
    }
  },
})

export const config = {
  matcher: [
    // Skip Next.js internals and all static files, unless found in search params
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    // Always run for API routes
    "/(api|trpc)(.*)",
  ],
}
