# coding=utf-8
# !/usr/bin/env python3
"""
The main script of pFuzzer.
"""
import os
import random
import shutil
import subprocess
import time
import socket
from threading import Thread

import core.PriorityHandling as PriorityHandling
import core.Utils as Utils
from core.TokenHandler import TokenHandler
from core.InputWrapper import InputWrapper
from core.SubstitutionExtractor import get_substitution
from core.TokenLearningHandler import TokenLearningHandler
from core.ParsingStageExtractor import ParsingStageExtractor

from typing import Tuple, Union, List

class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)

        self._return = None

    def run(self):
        if self._target is not None:
            print("Run %s with args %s and kwargs %s" % (str(self._target), str(self._args), str(self._kwargs)))
            self._return = self._target(*self._args, **self._kwargs)

    def join(self):
        Thread.join(self)
        return self._return


def run_and_trace(parentdir, inpt: Union[List[str], str], as_arg: bool, trace: bool = True) -> Tuple[int, bool]:
    """
    Executes the C code and runs the tracing on it.
    :param parentdir: The directory in which the program under test lies in.
    :param inpt: The input to use to run the program. For sockets its a list of commands to send.
    :param as_arg: Defines if the input is given as argument or via stdin.
    :param trace: Check if tracing should be performed or running only
    """
    global po
    timeout = False
    if trace:
        run_subject = "%s.instrumented" % Utils.subject
    else:
        run_subject = "%s.uninstrumented" % Utils.subject

    if as_arg:
        try:
            exit_code = subprocess.call([run_subject, Utils.g_flag, inpt], timeout=10)
        except subprocess.TimeoutExpired:
            exit_code = 0

    elif Utils.socketport != -1:
        cmd_inpt = [inpt, "proFuzzer End"]
        try:
            p = subprocess.Popen([run_subject])
            #call_thread = ThreadWithReturnValue(target=subprocess.call, args=([run_subject], ), kwargs={"timeout" : 1000})
            #call_thread.start()

            sck = None
            connected = False
            while not connected:
                try:
                    time.sleep(0.5)
                    print("Try connect.")
                    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                    print("Socket created: %s" % str(sck))
                    sck.connect(("127.0.0.1", Utils.socketport))
                    connected = True
                except Exception as e:
                    # print("Exception raised:")
                    sck.close()
                    sck = None
                    p.kill()
                    p = subprocess.Popen([run_subject])
                    print("\t%s" % str(e))
                    pass  # Do nothing, just try again
            for command in cmd_inpt:
                # command += '\x04'
                print(repr("Send: %s" % command))
                try:
                    sck.sendall(bytes(command, "utf-8"))
                    time.sleep(1)
                except BrokenPipeError:
                    print("Connection closed, see you next time.")
                    break

            #exit_code = call_thread.join()
            sck.close()
            sck = None
            exit_code = p.wait(timeout=10)
            print("Finished with exit code %d" % exit_code)

        except subprocess.TimeoutExpired:
            p.kill()
            exit_code = 0

    else:
        ps = subprocess.Popen(('printf', '%s', inpt), stdout=subprocess.PIPE)
        try:
            if Utils.g_flag:
                exit_code = subprocess.call([run_subject] + Utils.g_flag.split(" "), timeout=10, stdin=ps.stdout)
            else:
                exit_code = subprocess.call([run_subject], timeout=10, stdin=ps.stdout)
        except subprocess.TimeoutExpired:
            print("Timed out.")
            timeout = True
            exit_code = 0

    if trace:
        output = os.path.join(parentdir, "output")
        if os.path.exists("output"):
            shutil.move("output", output)
            outputgz = os.path.join(parentdir, "output.gz")
            os.system("rm -f %s && gzip %s" % (outputgz, output))
            me = os.path.join(parentdir, "metadata")
            po = os.path.join(parentdir, "pyg.txt")
            t = os.path.join(parentdir, "output.gz")
            os.system("%s/../install/bin/trace-taint -me %s -po %s -t %s" % (Utils.cwd, me, po, t))
        else:
            pass

    if exit_code == 0:
        if not trace:
            # run again with tracing if tracing was not done
            run_and_trace(parentdir, inpt, as_arg)

    return exit_code, timeout





def run_loop(parentdir, arg: bool, dfs: bool = False):
    """
    Runs the program under test several times with different inputs inferred through the tainting data gained of previous
    program runs.
    :param parentdir: The folder in which the program under test lies in.
    :param arg: The flag to indicate if the value is given to the program as arg or via stdin (true for as arg)
    :param dfs: The search strategy, by default bfs is used (dfs is false).
    :return:
    """
    # set of already generated inputs
    already_generated = set()

    # run program with starting random input (or a given input from the command line)
    if args.prefix:
        inp = args.prefix
    else:
        inp = random.choice(Utils.continuations)
    # inp = "SSH-2.4-Fz6Y1t9Ew\nasdf"
    # inp = ' 2//\n-= ( ) { HU5] 2/;'
    # inp = 'abc def345678a'
    # inp = 'N'

    inp_rand_new = inp
    already_generated.add(inp)
    Utils.all_exec = 1
    stop_function_found = False
    # the counter for the generated inputs
    inpt_counter = 0
    # hold a list of possible substitutions, take always the first element of the list and use this for continuation
    parent_input = None
    # predictor = Predictor(Executor(parentdir))
    with open(os.path.join(parentdir, "valid_inputs.txt"), "w") as valid_inputs_file:
        with open(os.path.join(parentdir, "crashes.txt"), "w") as error_inputs_file:
            with open(os.path.join(parentdir, "stats.txt"), "w") as Utils.stats_file:
                exit_code, timeout = run_and_trace(parentdir, inp, arg)
                (h_value, new_covered, values, knowledge, all_covered, last_assert, stop_function_found) = get_substitution(os.path.join(parentdir, "pyg.txt"),
                                                                             inp_rand_new,
                                                                             parent_input.prio_value.stack if parent_input else [],
                                                                             exit_code == 0,
                                                                             dfs)
                Utils.current_iteration = 1
                while True:
                    # keep track of how many input are executed since the last valid input
                    # check if the previous input was accepted or the input is larger than X chars, if so restart
                    # if h_value.cover_counter[0] > 0 and success and exit_code == 1:
                    #     (h_value, new_covered, values, knowledge, all_covered, inp_rand_new, success) = predictor.process(inp_rand_new[:-1])
                    #     if success:
                    #         exit_code = 0
                    #     else:
                    #         exit_code = 1
                    if Utils.current_iteration > MAX_ITERATIONS:
                        return
                    if len(Utils.seed_for_afl) > VALID_INPUTS:
                        return
                    if stop_function_found:
                        print(f"Stop function found (triggering input printed to {os.path.join(g_parentdir, 'stopinput.txt')}):\n{inp_rand_new}")
                        with open(os.path.join(g_parentdir, "stopinput.txt"), "w") as stop_input_file:
                            stop_input_file.write(inp_rand_new)
                        return
                    if not exit_code == 0 and len(inp) < 2000 and not last_assert:
                        # in this case some special error occurred and we add the value to the error file
                        print("\n\nH_Value parent: %s" % str(parent_input.prio_value if parent_input else "None"))
                        print("\nH_Value executed: %s\n\tfrom: %s\n\t#new values:%d\n\n" % (str(h_value), repr(inp_rand_new), len(values)))
                        error_inputs_file.write("Time used until input was generated: %f. Crash with exit code %d\n" % (time.time() - Utils.starttime, exit_code))
                        error_inputs_file.write(repr(inp_rand_new) + "\n\n")
                        error_inputs_file.flush()
                        inpt_counter = PriorityHandling.add_values_to_prioqueue(h_value, inpt_counter, new_covered, values, parent_input)
                    elif exit_code == 0 or last_assert:
                        # in this case the exit code was 0 or the last instruction was a call to assert, the call to assert claims a semantic check that we do not handle in pFuzzer by now
                        success = True
                        # if successful restart but do not consider
                        print("\n\nH_Value parent: %s" % str(parent_input.prio_value if parent_input else "None"))
                        print("\nH_Value executed: %s\n\tfrom: %s\n\t#new values:%d\n\n" % (str(h_value), repr(inp_rand_new), len(values)))
                        # we check if a new branch was covered and only report those inputs, otw. just go on with the search
                        # this lowers quantity a lot but improves quality significantly
                        if all_covered.issubset(Utils.valid_covered.keys()):
                            # combine covered lines of valid inputs with the ones covered by the current input to make sure that the
                            # heuristic value gets better only if new branches are covered
                            if Utils.printall and not last_assert:
                                valid_inputs_file.write("Time used until input was generated: %f\n" % (time.time() - Utils.starttime))
                                valid_inputs_file.write(repr(inp_rand_new) + "\n\n")
                                valid_inputs_file.flush()
                            Utils.valid_found.add(inp_rand_new)
                            inpt_counter = PriorityHandling.add_values_to_prioqueue(h_value, inpt_counter, new_covered, values, parent_input)
                        else:
                            # if the input was valid and covered new branches, we report it and restart the search but this time only inputs that cover branches that were not
                            # covered by valid inputs get a better heuristic value
                            if not last_assert:
                                # if the last instruction was a call to assert we did not find a valid input, so we should not add it to the valid inputs
                                valid_inputs_file.write("Time used until input was generated: %f\n" % (time.time() - Utils.starttime))
                                valid_inputs_file.write(repr(inp_rand_new) + "\n\n")
                                valid_inputs_file.flush()
                                Utils.valid_found.add(inp_rand_new)
                                if not timeout:
                                    Utils.seed_for_afl.add(inp_rand_new)
                                Utils.current_iteration = 0
                            # store which branches are covered additionally by the valid inputs
                            for key in all_covered:
                                if key in Utils.valid_covered:
                                    Utils.valid_covered[key] += 1
                                else:
                                    Utils.valid_covered[key] = 1
                            # set the currently covered branches to the ones covered by the valid inputs, hence the new heuristic value is based on the
                            # branches not seen before for the next round

                            inpt_counter = PriorityHandling.add_values_to_prioqueue(h_value, inpt_counter, new_covered, values, parent_input)
                            PriorityHandling.re_evaluate_queue()

                    # flag to control if only the random new input is executed
                    only_rand_new = False
                    while inp in already_generated and inp_rand_new in already_generated:
                        # first check if any possible tokens need to be learned
                        if TokenLearningHandler.tokens_to_learn():
                            inp = TokenLearningHandler.get_to_test()
                            inp_rand_new = inp
                            parent_input = None
                            only_rand_new = True
                        # if not continue with generating new inputs
                        elif Utils.inputs.empty():
                            print("[info] Nothing more to explore, search space is exhausted. Try new random value.")
                            # raise RuntimeError("Search space exhausted. Giving up exploration.")
                            inp = random.choice(Utils.continuations)
                            inp_rand_new = random.choice(Utils.continuations) + random.choice(Utils.continuations)
                            parent_input = None
                            # TODO May be necessary to populate the initial input space with all ascii chars as otw. some possible values may be missed
                            # # reset heuristic value, prio queue and already generated set to start with next round
                            # Utils.inputs = queue.PriorityQueue()
                            # # reset the currently covered branches to the ones covered by the valid inputs, hence the new heuristic value is based on the
                            # # branches not seen before for the next round
                            # already_generated = set()
                            # # also reset the covered paths as otw. the search space might get exhausted too early after restarting
                            # Utils.covered_paths.clear()
                            # # start with a new random input for the next round
                            # inp = random.choice(Utils.continuations)
                            # inp_rand_new = inp
                            # break
                        else:
                            parent_input: InputWrapper = Utils.inputs.pop()
                            inp, inp_rand_new = parent_input.val.get_corrections()
                            only_rand_new = inp in already_generated or parent_input and not parent_input.val.do_append
                            print("Smallest in Heap: %s\n\tValue: %s\n\tStack: %d\n" % (str(Utils.inputs.heap[0].prio_value), Utils.inputs.heap[0].val, Utils.inputs.heap[0].val.stack_size) if Utils.inputs.heap else ("PrioQueue is currently empty.", ""))

                    if not only_rand_new:
                        print(repr(inp) + "\n")
                        already_generated.add(inp)
                        Utils.current_iteration += 1

                        exit_code, timeout = run_and_trace(parentdir, inp, arg, False)
                        Utils.all_exec += 1
                        if exit_code == 0:
                            if parent_input:
                                # if the random extension was not executed, put the input back in the queue and re-evaluate it
                                # to make sure, that the input is re-evaluated early, reduce the same_path_taken value by 1 (this value is used as a first measurement to define when a value is executed)
                                parent_input.prio_value.same_path_taken = - 1
                                Utils.inputs.push(parent_input)
                            Utils.current_iteration += 1
                            Utils.all_exec += 1  # this was again executed as the first run of inp is w/o instrumentation
                            (h_value, new_covered, values, knowledge, all_covered, last_assert, stop_function_found) = get_substitution(os.path.join(parentdir, "pyg.txt"),
                                                                                         inp,
                                                                                         parent_input.prio_value.stack if parent_input else [],
                                                                                         exit_code == 0,
                                                                                         dfs)
                            if not all_covered.issubset(Utils.valid_covered.keys()):
                                inp_rand_new = inp
                                continue

                    print("Number of executions: %d\nApprox. Search Space Size: %d\nExecuted since last found: %d\n" % (Utils.all_exec, len(Utils.inputs), Utils.current_iteration))
                    print_stats_file()
                    already_generated.add(inp_rand_new)
                    Utils.current_iteration += 1
                    print(repr(inp_rand_new) + "\n")
                    exit_code, timeout = run_and_trace(parentdir, inp_rand_new, arg)
                    Utils.all_exec += 1
                    print_stats_file()
                    (h_value, new_covered, values, knowledge, all_covered, last_assert, stop_function_found) = get_substitution(os.path.join(parentdir, "pyg.txt"),
                                                                                 inp_rand_new,
                                                                                 parent_input.prio_value.stack if parent_input else [],
                                                                                 exit_code == 0,
                                                                                 dfs)


def print_stats_file():
    """
    Report stats in stats file.
    """
    Utils.stats_file.seek(0)
    Utils.stats_file.write("String to Token Mapping:\n")
    Utils.stats_file.write(TokenHandler.print_tokenmap())
    Utils.stats_file.write("\nParsing Stage Mapping:\n")
    Utils.stats_file.write(ParsingStageExtractor.print_stages())
    Utils.stats_file.write("\n")
    Utils.stats_file.write("Smallest in Heap: %s\n\tValue: %s\n\tStack: %d\n" % (str(Utils.inputs.heap[0].prio_value), Utils.inputs.heap[0].val, Utils.inputs.heap[0].val.stack_size) if Utils.inputs.heap else "PrioQueue is currently empty.")
    Utils.stats_file.write("\n")
    Utils.stats_file.write("Number of executions: %d\nApprox. Search Space Size: %d\nExecuted since last found: %d\nRuntime (seconds): %d\n" % (Utils.all_exec, len(Utils.inputs), Utils.current_iteration, time.time() - Utils.starttime))
    Utils.stats_file.flush()


def print_afl():
    """
    Prints the dictionary and seed to the afl folder. Mock values given as test and dict input if nothing was created.
    :return:
    """
    os.makedirs(os.path.join(g_parentdir, "afl", "dict"), exist_ok=True)
    os.makedirs(os.path.join(g_parentdir, "afl", "tests"), exist_ok=True)
    dict_counter = 0
    tokens = TokenHandler.tokens()
    if not tokens:
        with open(os.path.join(g_parentdir, "afl", "dict", "entry%d" % dict_counter), "w") as afl_dict:
            afl_dict.write(" ")
            dict_counter += 1
    for entry in tokens:
        with open(os.path.join(g_parentdir, "afl", "dict", "entry%d" % dict_counter), "w") as afl_dict:
            afl_dict.write(entry)
            dict_counter += 1
    # create an empty test if no seeds are available to fulfill the requirement of afl to have at least one valid test
    test_counter = 0
    if not Utils.seed_for_afl:
        with open(os.path.join(g_parentdir, "afl", "tests", "test%d" % test_counter), "w") as test_file:
            test_file.write(" ")
            test_counter += 1
    for val in Utils.seed_for_afl:
        with open(os.path.join(g_parentdir, "afl", "tests", "test%d" % test_counter), "w") as test_file:
            # avoid inputs that cause the afl instrumented version of lisp to crash
            if not val.startswith(" ( # "):
                test_file.write(val)
                test_counter += 1


if __name__ == '__main__':
    MAX_ITERATIONS = int(os.environ.get('MAX_ITER', '10000'))
    VALID_INPUTS = int(os.environ.get('VALID_INPUTS', '10'))
    # save time when execution started to later report when the inputs were generated
    Utils.starttime = time.time()
    import argparse

    rseed = int(os.environ.get('RSEED', '0'))
    random.seed(rseed)
    parser = argparse.ArgumentParser(description="proFuzzer")
    parser.add_argument('-p', "--program", metavar="subject", type=str,
                        help="The path to the subject as c file to run on.", required=True)
    parser.add_argument('-a', "--arg", metavar="arg", default="False", type=str,
                        help="Defines if the input is given as argument or via stdin.", required=True)
    parser.add_argument('-i', "--instrument", metavar="instrument", default="True", type=str,
                        help="Defines if the program under test gets instrumented.", required=True)
    parser.add_argument('-f', "--flag", metavar="flag", default="", type=str,
                        help="Defines the flag that is used if the program gets the argument over the command line.", required=False)
    parser.add_argument('-s', "--socket", metavar="socket", default=-1, type=int,
                        help="If present, the program will be fuzzed over a socket connection on the given port.", required=False)
    parser.add_argument('-pa', "--printall", metavar="printall", default="False", type=str,
                        help="If present, proFuzzer will output all valid inputs instead of only those which are covering new code.", required=False)
    parser.add_argument('-pf', "--prefix", metavar="prefix", default="@", type=str,
                        help="If present, the given string is used as a starting point from which it tries to close it. "
                             "The last character of the prefix will be used fo substitutions, so if you want to keep it add another random character to the prefix which is then used for substitution.", required=False)
    parser.add_argument('-fun', "--function", metavar="function", default="", type=str,
                        help="If present, proFuzzer will stop as soon as the given function was traversed by an input. If found, the respective input will be written to \"stopinput.txt\" in the target subject folder).",
                        required=False)

    args = parser.parse_args()
    Utils.subject = os.path.abspath(args.program)
    Utils.as_arg = args.arg.lower() == "true"
    instrument = args.instrument.lower() == "true"
    Utils.printall = args.printall.lower() == "true"
    Utils.stop_function = args.function

    Utils.socketport = args.socket

    # instrument program
    Utils.cwd = os.getcwd()
    if instrument:
        os.system("%s/../install/bin/trace-instr %s %s/../samples/excluded_functions" % (Utils.cwd, Utils.subject, Utils.cwd))
    Utils.g_flag = ""
    if args.flag:
        Utils.g_flag = "-%s" % args.flag
    g_parentdir = os.path.abspath(os.path.join(Utils.subject, os.pardir))

    os.chdir(g_parentdir)

    run_loop(g_parentdir, Utils.as_arg)

    print_afl()

    with open("timer.txt", "w") as timer:
        timer.write("%f\n%f" % (Utils.starttime, time.time()))
