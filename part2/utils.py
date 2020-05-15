import csv
from grid import location_to_cell_id


def read_csv(filename):
    with open(filename) as csv_file:
        r = csv.DictReader(csv_file, delimiter=' ')
        return list(r)


def get_users_from_queries(queries):
    return list(set(map(lambda x: x['ip_address'], queries)))


def get_user_daily_report(user, queries):
    user_queries = filter(lambda x: x['ip_address'] == user, queries)
    report = {}
    for record in user_queries:
        time = int(float(record['timestamp']))
        day = int(time / 24)
        hour = int(time % 24)

        if day not in report:
            report[day] = {}

        if hour not in report[day]:
            report[day][hour] = {
                "lat": record['lat'],
                "lon": record['lon'],
                "poi_types": [],
            }

        report[day][hour]["poi_types"].append(record["poi_type_query"])

    return report
