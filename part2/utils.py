import csv
from grid import location_to_cell_id
from geopy.distance import distance
from itertools import groupby


pois_types = {'appartment_block': 'home',
              'bar': 'entertainment',
              'cafeteria': 'entertainment',
              'club': 'entertainment',
              'company': 'work',
              'dojo': 'sport',
              'gym': 'sport',
              'laboratory': 'work',
              'office': 'work',
              'restaurant': 'entertainment',
              'supermarket': 'home',
              'villa': 'home',
              }


def n_top_loc(queries, n=2, all=False):
  d = {}
  for q in queries:
    loc = (float(q['lat']), float(q['lon']))
    if loc in d:
      d[loc] += 1
    else:
      d[loc] = 1
    
  if all:
    return sorted(list(d.items()), key=lambda x: x[1], reverse=True)
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

def get_user_infos(users, queries, pois):
    user_infos = {}

    for user in users:
        locs = {}
        users_queries = list(filter(lambda x: x['ip_address'] == user, queries))
        for loc in n_top_loc(users_queries, 3):
            grid = location_to_cell_id(loc[0][0], loc[0][1])
            curr_pois = filter(lambda x: int(x['cell_id']) == grid, pois)
            min_dist = None
            min_type = None
            for curr_poi in curr_pois:
                d = distance(loc[0], (float(curr_poi['lat']), float(curr_poi['lon']))).km
                if min_dist is None or d < min_dist:
                    min_dist = d
                min_type = curr_poi['poi_type'], curr_poi['poi_id']
                if pois_types[min_type[0]] == 'home':
                    locs['home'] = min_type[1]
                elif pois_types[min_type[0]] == 'work':
                    locs['work'] = min_type[1]
                elif pois_types[min_type[0]] == 'sport':
                    locs['sport'] = min_type[1]

        user_infos[user] = locs

    return user_infos

def get_families(user_infos, pois):
    families = {}
    grouped = groupby(sorted(list(user_infos.items()), key=lambda x: x[1]['home']), lambda x:x[1]['home'])
    for key, fam in grouped:
        if list(filter(lambda x: x['poi_id'] == key, pois))[0]['poi_type'] == 'appartment_block':
            pass
        members = []
        for member in fam:
            members.append(member[0])
            families[key] = members
    return families

