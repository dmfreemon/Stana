class Util:
    @staticmethod
    def my_total_seconds(td):
        return ((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) * 1.0) / 10**6

