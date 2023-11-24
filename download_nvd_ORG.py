import asyncio
import os
from aiohttp import ClientSession, TCPConnector
import datetime

class NVD_Source:
    def __init__(self):
        self.cache_dir_path = "/home/escan/181023/data_source"
        self.cache_dir_name = "nvd"
        self.cachedir = os.path.join(self.cache_dir_path, self.cache_dir_name)
        self.session = None

    async def download_cve_data(self):
        if not self.session:
            connector = TCPConnector(limit_per_host=19)
            self.session = ClientSession(connector=connector)

        # Create the cache directory if it doesn't exist
        os.makedirs(self.cachedir, exist_ok=True)

        current_year = datetime.datetime.now().year
        base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"

        # Create a list to store downloaded file paths
        downloaded_files = []

        for year in range(2002, current_year + 1):
            url_to_cve_data = f"{base_url}{year}.json.gz"
            filename = url_to_cve_data.split("/")[-1]
            filepath = os.path.join(self.cachedir, filename)

            # Check if the file already exists in the cache directory
            if not os.path.exists(filepath):
                async with self.session.get(url_to_cve_data) as response:
                    response.raise_for_status()

                    # Open the file and write the content
                    with open(filepath, "wb") as file:
                        while True:
                            chunk = await response.content.read(1024)
                            if not chunk:
                                break
                            file.write(chunk)
            
            # Append the downloaded file path to the list
            downloaded_files.append(filepath)

        # Close the session when done
        await self.session.close()
        self.session = None

        # Sort the downloaded files based on their filenames
        downloaded_files.sort()

if __name__ == "__main__":
    downloader = NVD_Source()
    asyncio.run(downloader.download_cve_data())

