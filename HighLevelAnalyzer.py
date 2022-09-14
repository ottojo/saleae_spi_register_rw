# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': '{{data.op}} address {{data.addr}}: {{data.data}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.current_op = None
        self.current_op_start = None
        self.current_addr = None

        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        
        if frame.data == {}:
            return None
        
        if self.current_addr is None:
            raw_addr = int.from_bytes(frame.data['mosi'], "big")
            if ((1<<7) & raw_addr) != 0:
                self.current_op = "write"
            else:
                self.current_op = "read"
            self.current_addr = raw_addr & ~(1<<7)
            self.current_op_start = frame.start_time
            return None
        else:
             # Return the data frame itself

            analyzer_result = AnalyzerFrame('mytype', self.current_op_start, frame.end_time, {
                'op': self.current_op,
                'addr': "{:#04x}".format(self.current_addr),
                'data': "{:#04x}".format(frame.data['mosi'][0] if self.current_op == "write" else frame.data['miso'][0])
            })
            self.current_addr = None
            return analyzer_result
        return None
       
