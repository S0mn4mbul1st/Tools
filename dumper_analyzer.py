#!/usr/bin/python2

import sys
import io
import json
import re

if 1:
    from Include.Tools.Logger import (
        get_log_file_path,
        initialize_logger,
        logger,
        initialize_json_logger,
    )

    from Include.IpBlocksDriversMade.IpBlocks import Ip_blocks
    from Include.MasterBcnAnalysis import MasterBcnAnalysis
    from Include.ResourceAllocationAnalysisMade.ResourceAllocationAnalysisMade import (
        ResourceAllocationAnalysisMade,
    )
    from Include.DdlConfigurationAnalysisMade import DdlConfigurationAnalysisMade
    from Include.DdlConfigurationAnalysisMadeEcpri import (
        DdlConfigurationAnalysisMadeEcpri,
    )
    from Include.DdlStatusAnalysisMade import DdlStatusAnalysisMade
    from Include.DdlStatusAnalysisMadeEcpri import DdlStatusAnalysisMadeEcpri
    from Include.CaMarkerEnableAnalysisMade import CaMarkerEnableAnalysisMade
    from Include.CaEndOfAcceptanceWindowAnalysisMade import (
        CaEndOfAcceptanceWindowAnalysisMade,
    )
    from Include.CaLocationAnalysisMade import CALocationAnalysisMade
    from Include.DpdInputPowerAnalysis import DPDInputPowerAnalysis
    from Include.SlaveBcnsAnalysis import SlaveBcnsAnalysis
    from Include.DulConfigurationAnalysisMade import DulConfigurationAnalysisMade
    from Include.DulStatusAnalysisMade import DulStatusAnalysisMade
    from Include.DulConfigurationAnalysisMadeEcpri import (
        DulConfigurationAnalysisMadeEcpri,
    )
    from Include.DulStatusAnalysisMadeEcpri import DulStatusAnalysisMadeEcpri
    from Include.CPRIforwardingAnalysisMade import CPRIforwardingAnalysisMade
    from Include.TimingsAnalysis import TimingsAnalysis
    from Include.DlFrontMeasurementAnlysisMade import DlFrontMeasurementAnalysisMade
    from Include.UlFrontMeasurementAnlysisMade import UlFrontMeasurementAnalysisMade
    from Include.DlFrontLevelPlanAnlysisMade import DlFrontLevelPlanAnalysisMade
    from Include.RTWPAnalysisMade import RTWPAnalysisMade
    from Include.DecompressionAndClockAnalysis import DecompressionAnalysis
    from Include.DecompressionAndClockAnalysis import (
        RecoveryClockControlandResetAnalysis,
    )
    from Include.GSMTimeslotAnalysisMade import GsmTimeslotAnalysisMade
    from Include.CarrierEnableAnalysisMade import CarrierEnableAnalysisMade
    from Include.TddTimerAnalysisMade import TddTimerAnalysisMade
    from Include.ProcessingDelaysAnalysisMade import ProcessingDelaysAnalysisMade

from Include.Rp1OmAnalysis import Rp1OmAnalysis


def match_and_collect(line, ip_blocks):
    for ip_block in ip_blocks.values():
        for registers_group in ip_block.values():
            if not registers_group.is_full():
                found = registers_group.found_pattern()
                if found or registers_group.find_pattern(line):
                    # print(registers_group.pattern.pattern, line)
                    registers_group.parse_words(line)


def cleanup(ip_blocks):
    for ip_block in ip_blocks.values():
        for registers_group in ip_block.values():
            registers_group.reset()


def getParam(dump_file, regex_str, max_lines):
    counter = 0
    for line in dump_file:
        # print(line, counter)
        madeNodeObj = re.search(regex_str, line)
        if madeNodeObj is not None:
            # print("found", regex_str)
            return madeNodeObj.group(1)
        counter = 1
        if counter == max_lines - 1:
            break


def getUnitType(manifest_str):
    if manifest_str is not None:
        unitObj = re.search("(\w )\.(\w )", manifest_str)
        if unitObj is not None:
            return unitObj.group(1), unitObj.group(2)


def getInstanceName(made_dump):
    return getParam(made_dump, "instanceName: (\w )", 9)


def getUnitVariantRevision(made_dump):
    manifest = getParam(made_dump, "manifest: (.*)", 4)
    return getUnitType(manifest)


def checkIfIsMade2(made_dump):
    madeVersion = getParam(made_dump, "Made (.*) Register Map version", 6)
    if madeVersion is not None:
        # print(madeVersion)
        return True
    return False


def analyze_made_dump_to_json(made_dump):
    result_string = io.StringIO()
    initialize_json_logger(logger, result_string)

    ip_blocks = Ip_blocks().ip_blocks

    for line in made_dump.readlines():
        line = line.decode(encoding="UTF-8", errors="replace").strip()
        match_and_collect(line, ip_blocks)

    analyze_made_dump(ip_blocks, [], None)

    log_contents = result_string.getvalue()

    result = {}
    for line in log_contents.splitlines():
        json_line = json.loads(line)
        if not result.get(json_line["filename"]):
            result[json_line["filename"]] = [json_line]
        else:
            result[json_line["filename"]].append(json_line)
    return result


def analyze_made_dump(ip_blocks, rp1Results, isMade2):

    carrierEnableAnalysis = CarrierEnableAnalysisMade(ip_blocks)
    carrierEnableAnalysis.analyze()
    dlActive, ulActive = carrierEnableAnalysis.get_results()
    resourceAllocation = ResourceAllocationAnalysisMade(ip_blocks, isMade2)
    resourceAllocation.analyze(rp1Results)
    isEcpri, dlAllocation, ulAllocation, _, _, _ = resourceAllocation.get_results()

    if isMade2:
        cpriforwarding = CPRIforwardingAnalysisMade(ip_blocks)
        cpriforwarding.analyze()
        
    if isEcpri:
        ddlConfigurationEcpri = DdlConfigurationAnalysisMadeEcpri(ip_blocks)
        ddlConfigurationEcpri.analyze(dlAllocation)
        dulConfigurationEcpri = DulConfigurationAnalysisMadeEcpri(ip_blocks)
        dulConfigurationEcpri.analyze(ulAllocation)

        ddlStatusEcpri = DdlStatusAnalysisMadeEcpri(ip_blocks)
        ddlStatusEcpri.analyze(dlAllocation)
        dulStatusEcpri = DulStatusAnalysisMadeEcpri(ip_blocks)
        dulStatusEcpri.analyze(ulAllocation)

    else:
        ddlConfiguration = DdlConfigurationAnalysisMade(ip_blocks)
        ddlConfiguration.analyze(dlAllocation)
        dulConfiguration = DulConfigurationAnalysisMade(ip_blocks)
        dulConfiguration.analyze(ulAllocation)

        ddlStatus = DdlStatusAnalysisMade(ip_blocks)
        ddlStatus.analyze(dlAllocation)
        dulStatus = DulStatusAnalysisMade(ip_blocks)
        dulStatus.analyze(ulAllocation)

    if isMade2:
        gsm_ts = GsmTimeslotAnalysisMade(ip_blocks)
        gsm_ts.analyze(dlAllocation)

    processingDelays = ProcessingDelaysAnalysisMade(ip_blocks)
    processingDelays.analyze(dlAllocation)

    caEnable = CaMarkerEnableAnalysisMade(ip_blocks)
    caEnable.analyze()
    caWindowEnd = CaEndOfAcceptanceWindowAnalysisMade(ip_blocks)
    caWindowEnd.analyze()
    caLocation = CALocationAnalysisMade(ip_blocks)
    caLocation.analyze(dlAllocation, caEnable, caWindowEnd, dlActive)
    dfeCaMarkers, jesdCaMarkers = caLocation.get_results()

    dlFrontMeas = DlFrontMeasurementAnalysisMade(ip_blocks)
    dlFrontMeas.analyze(dlAllocation)
    ulFrontMeas = UlFrontMeasurementAnalysisMade(ip_blocks)
    ulFrontMeas.analyze(ulAllocation)
    ulFrontMeasurements = ulFrontMeas.get_results()

    dlFrontPtx = DlFrontLevelPlanAnalysisMade(ip_blocks)
    dlFrontPtx.analyze(dlAllocation)

    if not isEcpri:
        rtwp = RTWPAnalysisMade(ip_blocks)
        rtwp.analyze(ulFrontMeasurements)

    tddTimer = TddTimerAnalysisMade(ip_blocks)
    tddTimer.analyze()


def analyze_made_dump_to_console_file():
    made_dump_path = ""
    rp1om_file_path = ""

    # sys.argv.append(made_dump_path)
    # sys.argv.append(rp1om_file_path)
    ip_blocks = Ip_blocks().ip_blocks

    if len(sys.argv) == 3:
        rp1om_file_path = sys.argv[2]

    if len(sys.argv) >= 2:
        made_dump_path = sys.argv[1]

        log_file_path = get_log_file_path(made_dump_path)

        initialize_logger(logger, log_file_path)

    else:
        initialize_logger(logger)
        logger.error("Usage: Pass MADE Dfe dump file path as argument")

    try:
        rp1Results = None
        nodeId = None
        with open(made_dump_path, "r") as made_dump:
            # nodeId = getInstanceName(made_dump)
            isMade2 = checkIfIsMade2(made_dump)
            for line in made_dump:
                match_and_collect(line, ip_blocks)

        try:
            if rp1om_file_path:
                rp1omAnalysis = Rp1OmAnalysis()
                rp1omAnalysis.analyze(rp1om_file_path)
                rp1Results = rp1omAnalysis.get_results()

        except StandardError as err:
            logger.error("Failed to analyze the file. This analysis will be ignored.")

        analyze_made_dump(ip_blocks, rp1Results, isMade2)

    except IOError as err:
        logger.error(
            "File: {}, Args: {}".format(err.filename, [arg for arg in err.args])
        )


if __name__ == "__main__":
    analyze_made_dump_to_console_file()
