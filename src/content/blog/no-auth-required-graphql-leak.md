---
title: "No Auth Required: How One GraphQL Query Exposed 27,000+ Home Addresses"
description: "A writeup of my first bug bounty submission, detailing how a public-by-design GraphQL query exposed over 27,000 personal home addresses due to a platform integration flaw."
pubDate: "2026-07-17"
heroImage: "../../assets/images/graphql.png"
---

I was running subfinder on a target and sifting through the output when something caught my eye: a cluster of `api-` prefixed subdomains. That's usually worth a closer look.

I pulled them up and checked for exposed GraphQL schemas. They had one. So I did what you do: started running through queries to see what I actually had access to.

## Finding the Data

Schema introspection was open, which made mapping the surface easy. I went through the available queries one by one. Most of the sensitive ones were properly gated: customer profiles, orders, payment methods, all required auth. Normal stuff.

Then I hit `pickupLocations`. Ran it:

```bash
curl -s "https://<cc>-api.<target>/graphql" \
  -X POST -H "Content-Type: application/json" \
  -d '{"query":"{pickupLocations{total_count,items{name,email,street,city,postcode}}}"}'
```

Got results back. Names, emails, addresses. Lots of them.

That immediately looked off. Not because the query failed to auth-gate (Magento's `pickupLocations` is unauthenticated by design, it's built for store locators), but because the *data itself* looked personal. Personal email addresses. Residential-looking street addresses. These didn't look like business contacts.

So I went and checked the actual site.

## The Confirmation

The marketplace was a secondhand platform where individual people sell their own stuff. The sellers *were* the pickup locations. When I looked at how the site presented them, it was deliberately vague: first name, approximate city, and an explicit disclaimer that the location wasn't exact. No email. No street. No postal code.

That's when it clicked. The API was returning the full record for every single seller on the platform, with no authentication required. The site was going out of its way to protect that data. The GraphQL layer was just handing it out.

## The Scale of It

I paginated through to confirm it wasn't a cached subset:

```bash
curl -s "https://<cc>-api.<target>/graphql" \
  -X POST -H "Content-Type: application/json" \
  -d '{"query":"{pickupLocations(pageSize:3,currentPage:50){items{name,email,street,city,postcode}}}"}'
```

Different records on every page. Full dataset, fully enumerable. Same query, same result across three country instances:

- **Instance 1:** 58 records, including staff with corporate email addresses tied to their home addresses
- **Instance 2:** 17,546 records
- **Instance 3:** 10,080 records

**Total: 27,684 individuals.** Two more instances existed but were unreachable during testing due to TLS errors.

I stopped there. Minimum data to prove the finding, PII redacted in screenshots, everything deleted afterward, and wrote it up.

## Why It Happened

Neither Magento nor the marketplace extension was doing anything wrong individually.

Magento's `pickupLocations` is public by design. It exists so shoppers can find nearby physical store locations without logging in. The default type includes fields like name, email, street, city, postcode, fine for a business storefront's contact details.

The marketplace extension maps each seller to a pickup location so buyers can arrange collection. That also makes sense on its own.

The problem is that Magento treats pickup location data as public business information, and the extension is populating it with private individual data: home addresses, personal emails. Magento serves it publicly because that's what the system was designed for. The extension never accounted for the fact that in a peer-to-peer context, "seller contact details" and "personal home address" are the same thing.

It's the kind of bug that makes it through review because every individual piece looks correct.

## Disclosure

The program runs as a public VDP that can get you invited to a private bug bounty program for severe findings. Reported through it, triaged in about 21 hours, accepted as Critical.

Resolved. Bounty paid: **$1,000**. My first ever bug bounty submission.
