import { redirect } from "next/navigation";

/**
 * The overview lives at `/`; this is the same page under the name the sidebar
 * uses.
 *
 * A URL is something people paste - into a chat, a document, a ticket. Asking
 * them to remember that the overview is the root and every other tool has a
 * path is a way of producing 404s for no reason; this makes the name that is
 * actually shown in the interface resolve to the page it names.
 */
export default function OverviewAlias() {
  redirect("/");
}