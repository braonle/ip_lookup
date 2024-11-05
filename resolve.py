#!/usr/bin/env python3
import argparse
import logging
import json
import glob
import os
from datetime import datetime
from ip_lookup.lookup import RirSearcher, DEFAULT_CACHE_FILE

logging.basicConfig(format="{asctime} [{module}:{lineno}] [{levelname}] {message}", style="{",
                    datefmt="%d/%m/%Y %H:%M:%S", level=logging.INFO)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Resolve IP addresses into RIR info and FQDN")
    parser.add_argument('-l', '--list', type=str, nargs="?", dest="ip_list_filename",
                        const="", metavar="FILE", default=None,
                        help='filename for the list of IP addresses; latest .txt used by default')
    parser.add_argument('-c', '--cache', type=str, dest="cache_filename",
                        metavar="FILE", default=DEFAULT_CACHE_FILE,
                        help=f"cache filename; '{DEFAULT_CACHE_FILE}' is used by default")
    parser.add_argument('-x', '--excel', type=str, nargs="?", dest="excel_filename",
                        const="", metavar="FILE", default=None,
                        help="SSL inspection spreadsheet filename; latest .xlsx sed by default")
    parser.add_argument('--excel-export', nargs="?", dest="excel_export",
                        const="out.xlsx", metavar="FILE", default=None,
                        help='Export data to Excel')
    parser.add_argument('--json-export', nargs="?", dest="json_export",
                        const="out.json", metavar="FILE", default=None,
                        help='Export data to JSON')
    args = parser.parse_args()

    if args.ip_list_filename is None:
        ip_list_filename = None
    elif args.ip_list_filename == "":
        files = glob.glob("*.txt")
        files.remove("requirements.txt")
        if not files:
            logging.info("No .txt file was found in the directory of the application. \
                    IP list search is not used.")
            ip_list_filename = None
        else:
            ip_list_filename = max(files, key=os.path.getmtime)
    else:
        ip_list_filename = args.ip_list_filename

    if args.excel_filename is None:
        excel_filename = None
    elif args.excel_filename == "":
        files = glob.glob("*.xlsx")
        if not files:
            logging.info("No .xlsx file was found in the directory of the application. \
                    SSL inspection spreadsheet search is not used.")
            excel_filename = None
        else:
            excel_filename = max(files, key=os.path.getmtime)
    else:
        excel_filename = args.excel_filename

    st = datetime.now()

    rir = RirSearcher(cache_file_name=args.cache_filename)

    if ip_list_filename is not None:
        logging.info("Resolving IPs from text file %s", ip_list_filename)
        rir.reload_file(ip_file_name=ip_list_filename)
        rir.search_list()

        if args.json_export is not None:
            logging.info("Saving IPs from text file to JSON %s", args.json_export)
            output = []
            for x in rir.resolved_ip_list:
                output.append(x.to_dict())

            with open(args.json_export, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=4, default=list)

        if args.excel_export is not None:
            logging.info("Saving IPs from text file to Excel %s", args.excel_export)
            rir.to_excel(args.excel_export)

    if excel_filename is not None:
        logging.info("Resolving IPs from SSL inspection spreadsheet %s", excel_filename)
        rir.search_excel(excel_filename, ["SSL Dest Groups", "SSL Custom Categories"])

    et = datetime.now()
    logging.info("Script ran for %s seconds.", et - st)
