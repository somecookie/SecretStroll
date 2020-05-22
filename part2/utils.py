import csv
from grid import location_to_cell_id


def n_top_loc(queries, n):
    """
    If you want the top location of a specific user, the queries need to be filtered prior
    to the call to this function.
    """


def n_top_loc(queries, n):
    d = {}
    for q in queries:
        loc = (float(q['lat']), float(q['lon']))
        if loc in d:
            d[loc] += 1
        else:
            d[loc] = 1
    return sorted(list(d.items()), key=lambda x: x[1], reverse=True)[:n]


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
