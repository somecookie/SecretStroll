import bisect

class Grid:

    # Grid parameters
    # Top left corner of the area
    MAP_LAT = 46.5
    MAP_LON = 6.55

    # Total area size
    MAP_SIZE_LAT = 0.07
    MAP_SIZE_LON = 0.10


    def __init__(self, nbr_cells, pois):

        if nbr_cells <= 0:
            raise ValueError("The number of cells must be positive.")

        self.nbr_cells = nbr_cells
        self.grid_lat_points = [Grid.MAP_LAT + i * (Grid.MAP_SIZE_LAT / nbr_cells) for i in range(1, nbr_cells + 1)]
        self.grid_lon_points = [Grid.MAP_LON + i * (Grid.MAP_SIZE_LON / nbr_cells) for i in range(1, nbr_cells + 1)]
        self.pois = {}
        
        for p in pois:
            i = self.location_to_cell_id(float(p["lat"]), float(p["lon"]))

            if i not in self.pois:
                self.pois[i] = [p]
            else:
                self.pois[i].append(p)

    def location_to_cell_id(self, lat, lon):
        """Get the grid cell ID for a given latitude and longitude."""
        if not (Grid.MAP_LAT <= lat < Grid.MAP_LAT + Grid.MAP_SIZE_LAT) or not (Grid.MAP_LON <= lon < Grid.MAP_LON + Grid.MAP_SIZE_LON):
            raise ValueError("Out of area range.")

        i = bisect.bisect(self.grid_lat_points, lat)
        j = bisect.bisect(self.grid_lon_points, lon)
        return i * self.nbr_cells + j + 1

    def get_pois_from_coord(self, lat, lon):
            i = self.location_to_cell_id(lat, lon)
            if i in self.pois:
                return self.pois[i]
            else:
                return []

    def get_updated_pois(self):
        updated_pois = []

        for i in self.pois:
            for p in self.pois[i]:
                new_poi = p
                new_poi["cell_id"] = i
                updated_pois.append(new_poi)
        
        return updated_pois