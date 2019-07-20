from byexample.concern import Concern

class ProfilePerf(Concern):
    target = 'profile-perf'

    def __init__(self, **unused):
        self.i = 0

    def start(self, examples, runners, filepath, options):
        self.runners = runners
        self.options = options
        for runner in runners:
            if runner.language == 'python':
                profile_perf_start_code = r'''
import cProfile as __cProfile
__pr = __cProfile.Profile()
__pr.enable()
'''
                runner._exec_and_wait(profile_perf_start_code, options, timeout=10)
                break


    def start_example(self, example, options):
        options['timeout'] *= 10


    def finish(self, *args):
        for runner in self.runners:
            if runner.language == 'python':
                profile_perf_end_code = r'''
__pr.disable()
__pr.dump_stats("profile.perf.%i")
''' % self.i
                runner._exec_and_wait(profile_perf_end_code, self.options, timeout=10)
                break

        self.i += 1

