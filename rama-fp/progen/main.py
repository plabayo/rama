#!/usr/bin/env python3

from datetime import datetime
import os
import json
import psycopg
import time

def write_profile_to_file(row, f):
    f.write("UserAgentProfile {\n")
    for key, value in row.items():
        f.write(f"    {key}: {value},\n")
    f.write("}\n")


def main():
    # Get database connection string from environment variable
    database_url = os.environ.get("RAMA_FP_DATABASE_URL")
    if not database_url:
        print("Error: RAMA_FP_DATABASE_URL environment variable not set")
        return

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
                                    one_week_ago_ms = (time.time() - 7 * 24 * 60 * 60) * 1000
                                    if row[i].timestamp() * 1000 > one_week_ago_ms:
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

                print(f"Total profiles: {len(profiles)}")

    except Exception as e:
        print(f"Error connecting to database: {e}")

if __name__ == "__main__":
    main()
