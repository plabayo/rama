#!/usr/bin/env python3

import os
import json
import time

# Required by a TLS-enabled UserAgentProfile. Optional observations (fetch,
# XHR, WebSocket, JavaScript, etc.) do not determine completeness.
REQUIRED_PROFILE_FIELDS = (
    "h1_settings", "h1_headers_navigate", "h2_settings",
    "h2_headers_navigate", "tls_client_hello",
)


def report_profile_completeness(profiles):
    incomplete = 0
    for profile in profiles:
        missing = [name for name in REQUIRED_PROFILE_FIELDS if profile.get(name) is None]
        if missing:
            incomplete += 1
            print(f"Incomplete profile {profile['uastr']!r}: missing {', '.join(missing)}")
    print(f"Total profiles: {len(profiles)} ({len(profiles) - incomplete} complete, {incomplete} incomplete)")


def main():
    # Get database connection string from environment variable
    database_url = os.environ.get("RAMA_FP_DATABASE_URL")
    if not database_url:
        print("Error: RAMA_FP_DATABASE_URL environment variable not set")
        return

    # Keep diagnostics usable without installing the database driver.
    import psycopg

    # Connect to the database
    try:
        with psycopg.connect(f"{database_url}") as conn:
            # Create a cursor
            with conn.cursor() as cur:
                # Execute the query to select all rows from ua-profiles table
                cur.execute('SELECT * FROM "ua-profiles" ORDER BY uastr ASC')

                # Fetch all rows
                rows = cur.fetchall()

                # Get column names
                column_names = [desc[0] for desc in cur.description]

                with open(os.path.join(os.path.dirname(__file__), "../../rama-ua/src/profile/embed_profiles.json"), "w") as f:
                    profiles = []
                    for row in rows:
                        profile = {}
                        for i, col_name in enumerate(column_names):
                            if col_name == "updated_at":
                                if row[i]:
                                    updated_at = row[i].strftime("%Y-%m-%d %H:%M:%S")
                                    fourteen_days_ago_ms = (time.time() - 14 * 24 * 60 * 60) * 1000
                                    if row[i].timestamp() * 1000 > fourteen_days_ago_ms:
                                        profile[col_name] = updated_at
                                    else:
                                        print(f"skip profile #{i}: updated_at to far in the past: {updated_at}")
                                        profile = None
                                        break
                                else:
                                    print(f"skip profile #{i}: missing updated_at")
                                    profile = None
                                    break
                            else:
                                profile[col_name] = row[i]
                        if profile:
                            profiles.append(profile)

                    f.write(json.dumps(profiles, sort_keys=True))

                report_profile_completeness(profiles)

    except Exception as e:
        print(f"Error connecting to database: {e}")

if __name__ == "__main__":
    main()
