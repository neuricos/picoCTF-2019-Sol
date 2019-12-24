import re
import requests
import json
import sys

def main():
    s = 'picoCTF{(35.028309, 135.753082)(46.469391, 30.740883)(39.758949, -84.191605)(41.015137, 28.979530)(24.466667, 54.366669)(3.140853, 101.693207)_(9.005401, 38.763611)(-3.989038, -79.203560)(52.377956, 4.897070)(41.085651, -73.858467)(57.790001, -152.407227)(31.205753, 29.924526)}'

    pat = re.compile(r'\(\-?\d+\.\d+, \-?\d+\.\d+\)')

    coordinates = re.findall(pat, s)

    partial_url = "https://geocode.xyz/{}?json=1"

    answer = ""

    for coordinate in coordinates:
        query = re.sub(r'(\(|\)|\s)', '', coordinate)

        # complete the url
        url = partial_url.format(query)

        while True:
            print(f"Sending request to {url}")
            response = requests.get(url)

            if (response.status_code == 200):
                json_obj = json.loads(response.text)
                answer += json_obj['geocode'][0]
                break

    for c in answer:
        s = pat.sub(c, s, 1)

    print()
    print(f"FLAG: {s}")

if __name__ == '__main__':
    main()
