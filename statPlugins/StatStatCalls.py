#!/usr/bin/env python
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import sys
import operator

from StatBase import StatBase
from Util import Util

class StatStatCalls(StatBase):
    """ Stat and print stat calls of strace"""

    def __init__(self):
        self._fileStatList = {}
        self._pluginOptionDict = {}
        return

    def optionHelp(self):
        return {"output":"Write the output to this file instead of stdout"}

    def setOption(self, pluginOptionDict):
        self._pluginOptionDict = pluginOptionDict
        return True

    def getSyscallHooks(self):
        return_dict = {}
        #for syscall in ["read", "write", "open", "close"]:
        for syscall in ["stat"]:
            return_dict[syscall] = self.statStatCalls
        return return_dict

    def isOperational(self, straceOptions):
        return True

    # 1428504926.595877 stat("/home/lsstsw/stack/ups_db/sims_photUtils/master-gdb619108a7+1.version", {st_mode=S_IFREG|0664, st_size=398, ...}) = 0 <0.000018>
    # 1428504926.596596 stat("/home/lsstsw/stack/Linux64/sims_photUtils/master-gdb619108a7+1/ups/Linux64/sims_photUtils/master-gdb619108a7+1/ups/sims_photUtils.table", 0x7fffc442f1e0) = -1 ENOENT (No such file or directory) <0.009833>
    def statStatCalls(self, result):
        #if result["syscall"] in ["read", "write", "open", "close"]:
        if result["syscall"] in ["stat"]:
            filename = result["args"][0]
            rc = int(result["return"])
            callTime = Util.my_total_seconds(result["timeSpent"])

            if rc == 0:
                successfulCall = 1
            else:
                successfulCall = 0

            f = sys.stdout
            #f.write("====== File IO summary (csv) ======\n")
            #f.write("filename, returncode, seconds\n")
            f.write("%s, %s, %8.6f\n" % (filename, rc, callTime))

            # accumulate into totals array
            if filename not in self._fileStatList:
                # create new entry in array
                self._fileStatList[filename] = [1, callTime, successfulCall]
            else:
                # accumulate into existing entry in array
                self._fileStatList[filename][0] += 1
                self._fileStatList[filename][1] += callTime
                self._fileStatList[filename][2] += successfulCall

            return

    def printOutput(self):

        # filename = self._pluginOptionDict.get("output", "")
        # f = open(filename, "w") if filename else sys.stdout

        f = sys.stdout
        f.write("====== Stat Calls Summary ======\n")
        f.write("     total        total         time      successful    failed          \n")
        f.write("     calls        time        per call       calls       calls  filename\n")

        # sort by total time
        sorted_x = sorted(self._fileStatList.items(), key=lambda kvt: kvt[1][1] , reverse=True)
        #print sorted_x

        grandTotalCalls = 0
        grandTotalTime = 0

        for item in sorted_x:
        #for file in self._fileStatList:
            filename = item[0]
            totalCalls = item[1][0]
            totalTime = item[1][1]
            successfulCalls = item[1][2]

            grandTotalCalls += totalCalls
            grandTotalTime += totalTime
        
            #totalCalls = self._fileStatList[file][0]
            #totalTime = self._fileStatList[file][1]
            #successfulCalls = self._fileStatList[file][2]
            f.write("%10d  %12.6f  %12.6f  %10d  %10d  %s\n" % (  totalCalls,
                                                                totalTime,
                                                                totalTime / totalCalls,
                                                                successfulCalls,
                                                                totalCalls - successfulCalls,
                                                                filename.replace('"','')))


        f.write("Grand Totals\n")
        f.write("%10d  %12.6f  %12.6f  %10d  %10d  %s\n" % (  grandTotalCalls,
                                                              grandTotalTime,
                                                              0,
                                                              0,
                                                              0,
                                                              " "))
        return
