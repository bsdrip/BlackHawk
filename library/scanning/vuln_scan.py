from nmap3 import Nmap
import json
import logging
import os


class VulnScan:
    def __init__(self, target, args='', script_args='', log_level=logging.INFO):
        logging.basicConfig(level=log_level)
        self._target = target
        self._safe_target = target.replace("/", "_")
        self._script = "--script=vulners"
        self._script_args = f'--script-args={script_args}' if script_args else ''
        self._additional_args = args
        self._command_args = f"{self._script} {self._script_args} {self._additional_args}"
        logging.debug(
            "Initializing vulnerability scan: nmap -sV %s %s",
            self._command_args,
            self._target,
        )

    def run(self):
        self.nmap = Nmap()
        if self._has_results():
            logging.debug(
                "Found existing results for %s at results/%s_vuln.json",
                self._target,
                self._safe_target,
            )
            print(f"Found existing results for {self._target} at results/{self._safe_target}_vuln.json")
            print("Would you like to use these results? (y/N)")
            if input().lower() == "y":
                self._results = self._get_results()
                return
        logging.info("Running vulnerability scan on %s", self._target)
        self._results = self.nmap.nmap_version_detection(
            self._target,
            args=self._command_args,
        )
        logging.info("Vulnerability scan complete")
        self._output()

    def _output(self, directory="results"):
        logging.info("Writing vulnerability scan results to %s/%s_vuln.json", directory, self._safe_target)
        parent_dir = directory
        directory = self._safe_target
        path = os.path.join(parent_dir, directory)
        logging.info("Creating directory %s", path)
        os.makedirs(path, 0o777, exist_ok=True)
        with open(f'{path}/{self._safe_target}_vuln_scan.json', "w") as f:
            json.dump(self._results, f, indent=4)
        logging.info("Vulnerability scan results written to %s/%s_vuln.json", path, self._safe_target)

    def _get_results(self, directory="results"):
        try:
            with open(f'{directory}/{self._safe_target}/{self._safe_target}_vuln_scan.json', "r") as f:
                return json.load(f)
        except FileNotFoundError as error:
            logging.error(error)
            raise

    def _has_results(self, directory="results"):
        try:
            with open(f'{directory}/{self._safe_target}/{self._safe_target}_vuln_scan.json', "r"):
                return True
        except FileNotFoundError:
            return False

    def get_cves(self, directory="results"):
        cves = []
        for ip in self._results:
            if ip == 'runtime':
                break
            cves.append({"ip": ip, "ports": []})
            for port in self._results[ip]["ports"]:
                if "scripts" in port.keys():
                    for script in port['scripts']:
                        if script['name'] == 'vulners':
                            cves[-1]['ports'].append({
                                "port": port['portid'],
                                "cves": [],
                                "service": port['service'],
                            })
                            for cpe in script['data'].keys():
                                for cve in script['data'][cpe]['children']:
                                    if cve['type'] == 'cve':
                                        cves[-1]['ports'][-1]['cves'].append({
                                            "cve": cve['id'],
                                            "data": self._get_cve_details(cve['id'], logging),
                                        })
        cves = [cve for cve in cves if cve['ports']]
        file_name = f'{directory}/{self._safe_target}/{self._safe_target}_cves.json'
        with open(file_name, "w") as f:
            json.dump(cves, f, indent=4)
        logging.info("CVEs written to %s/%s", directory, file_name)
        return cves

    @staticmethod
    def _get_cve_details(cve, logger):
        logger.info("Getting details for %s", cve)
        current_dir = os.path.dirname(os.path.realpath(__file__))
        filename = f'{current_dir}/resources/nvd-json-data-feeds/CVE-{cve[4:8]}/CVE-{cve[4:-2]}xx/{cve}.json'
        logger.debug("Reading %s", filename)
        with open(filename, "r") as f:
            data = json.load(f)
        description = data['descriptions'][0]['value']
        if data['metrics'].get('cvssMetricV31', None):
            cvss_data = data['metrics']['cvssMetricV31'][0]['cvssData']
        elif data['metrics'].get('cvssMetricV2', None):
            cvss_data = data['metrics']['cvssMetricV2'][0]['cvssData']
        else:
            cvss_data = {}
        return {
            "description": description,
            "cvss": cvss_data,
        }
