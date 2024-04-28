"""
    Script to decode response packets
"""

# Copyright: Alistair Francis <alistair@alistair23.me>

import unittest
import binascii

from .models import MowerModels
from .helpers import crc, TaskInformation


class MowerResponse:
    def __init__(self, channel_id: int):
        self.channel_id = channel_id

    def decode_response_template(self, data: bytearray):
        if data[0] != 0x02:
            return None

        if data[1] != 0xFD:
            return None

        if data[3] != 0x00:
            return None

        id = self.channel_id.to_bytes(4, byteorder="little")
        if data[4] != id[0]:
            return None
        if data[5] != id[1]:
            return None
        if data[6] != id[2]:
            return None
        if data[7] != id[3]:
            return None

        if data[8] != 0x01:
            # This is a valid config, but we don't support it
            # return m1656b(decodeState, c10786f);
            return None

        if data[9] != crc(data, 1, 8):
            return None

        if data[10] != 0x01:
            return None

        if data[11] != 0xAF:
            return None

        # data[12], data[13] and data[14] are the request type

        if data[15] != 0x00:
            return None

        if data[16] != 0x00:
            return None

        return data

    def decode_response_device_type(self, data: bytearray):
        self.decode_response_template(data)

        # Length
        if data[17] != 0x02:
            return None

        if data[18] != 0x00:
            return None

        if data[21] != crc(data, 1, len(data) - 3):
            return None

        if data[22] != 0x03:
            return None

        return MowerModels[(data[19], data[20])]

    def decode_response_battery_level(self, data: bytearray):
        self.decode_response_template(data)

        # Length
        if data[17] != 0x01:
            return None

        if data[18] != 0x00:
            return None

        if data[20] != crc(data, 1, len(data) - 3):
            return None

        if data[21] != 0x03:
            return None

        return data[19]

    def decode_response_is_charging(self, data: bytearray):
        self.decode_response_template(data)

        # Length
        if data[17] != 0x01:
            return None

        if data[18] != 0x00:
            return None

        if data[20] != crc(data, 1, len(data) - 3):
            return None

        if data[21] != 0x03:
            return None

        return data[19]

    def decode_response_start_time(self, data: bytearray)->int | None:
        self.decode_response_template(data)

        # Length
        if data[17] != 0x04:
            return None

        if data[18] != 0x00:
            return None
        
        if data[23] != crc(data, 1, len(data) - 3):
            return None

        if data[24] != 0x03:
            return None

        unixtimestamp = int.from_bytes(data[19:23], byteorder='little', signed=False)
        return unixtimestamp

    def decode_response_mower_state(self, data: bytearray, is_husqvarna:bool=True) ->str|None:
        self.decode_response_template(data)

        # Length
        if data[17] != 0x01:
            return None

        if data[18] != 0x00:
            return None

        if data[20] != crc(data, 1, len(data) - 3):
            return None

        if data[21] != 0x03:
            return None

        state = data[19]
        if is_husqvarna:
            match state:
                case 1:
                    return "paused"
                case 2:
                    return "stopped"
                case 3:
                    return "error"
                case 4:
                    return "fatalError"
                case 5:
                    return "off"
                case 6:
                    return "checkSafety"
                case 7:
                    return "pendingStart"
                case 8:
                    return "waitForSafetyPin"
                case 9:
                    return "restricted"
                case 10:
                    return "inOperation"
                case 11:
                    return "unknown"
                case 12:
                    return "connecting"
                case 13:
                    return "pending"
                case 14:
                    return "disconnected"
                case _:
                    return "unknown"
        else:
            match state:
                case 0:
                    return "off"
                case 1:
                    return "waitForSafetyPin"
                case 2:
                    return "stopped"
                case 3:
                    return "fatalError"
                case 4:
                    return "pendingStart"
                case 5:
                    return "paused"
                case 6:
                    return "inOperation"
                case 7:
                    return "restricted"
                case 8:
                    return "error"
                case _:
                    return "unknown"

    def decode_response_mower_activity(self, data: bytearray):
        self.decode_response_template(data)

        # Length
        if data[17] != 0x01:
            return None

        if data[18] != 0x00:
            return None

        if data[20] != crc(data, 1, len(data) - 3):
            return None

        if data[21] != 0x03:
            return None

        state = data[19]

        match state:
            case 0:
                return "none"
            case 1:
                return "charging"
            case 2:
                return "goingOut"
            case 3:
                return "mowing"
            case 4:
                return "goingHome"
            case 5:
                return "parked"
            case 6:
                return "stoppedInGarden"
            case _:
                return "unknown"
    
    def decode_keepalive_response(self, data: bytearray) -> bool | None:
        self.decode_response_template(data)

        if data[12] != 0x42 and data[13] != 0x12:
            return False

        if data[14] != 0x02:
            return False

        return True

    def decode_response_park(self, data: bytearray) -> int | None:
        self.decode_response_template(data)

        if data[19] != crc(data, 1, len(data) - 3):
            return None
        if data[20] != 0x03:
            return None
        return 1

    def decode_getStartupSequenceRequiredResponse(self, data: bytearray) -> bool | None:
        self.decode_response_template(data)
        if data[17] == 0x01:
            return True
        return False

    def decode_is_operator_loggedin_response(self, data: bytearray) -> bool | None:
        self.decode_response_template(data)
        if data[17] == 0x01:
            return True
        return False

    def decode_get_mode_response(self, data:bytearray):
        self.decode_response_template(data)
        if data[17] != 0x01:
            return None

        if data[18] != 0x00:
            return None
        if data[20] != crc(data, 1, len(data) - 3):
            return None

        if data[21] != 0x03:
            return None

        state = data[19]

        match state:
            case 0:
                return "auto"
            case 1:
                return "manual"
            case 2:
                return "home"
            case 3: 
                return "demo"

    def decode_get_serial_number_response(self, data: bytearray):
        self.decode_response_template(data)
         # Length
        if data[17] != 0x04:
            return None

        if data[18] != 0x00:
            return None

        if data[23] != crc(data, 1, len(data) - 3):
            return None

        if data[24] != 0x03:
            return None

        vale = int.from_bytes(data[19:23], byteorder='little', signed=False)
        return vale

    def decode_get_restriction_reason_response(self, data: bytearray):
        self.decode_response_template(data)

        # Length
        if data[17] != 0x01:
            return None

        if data[18] != 0x00:
            return None

        if data[20] != crc(data, 1, len(data) - 3):
            return None

        if data[21] != 0x03:
            return None

        state = data[19]

        match state:
            case 0:
                return "none"
            case 1:
                return "week_schedule"
            case 2:
                return "park_override"
            case 3:
                return "sensor"
            case 4:
                return "daily_limit"
            case 5:
                return "fota"
            case 6:
                return "frost_sensor"
            case 7:
                return "all_missions_complete"
    
    def decode_get_number_of_tasks_response(self, data: bytearray) -> int:
        self.decode_response_template(data)

        # Length
        if data[17] != 0x04:
            return None

        if data[18] != 0x00:
            return None

        if data[23] != crc(data, 1, len(data) - 3):
            return None

        if data[24] != 0x03:
            return None

        vale = int.from_bytes(data[19:23], byteorder='little', signed=False)
        return vale

    def decode_set_override_mow_response(self, data: bytearray) -> bool | None:
        self.decode_response_template(data)
        # TODO: check response values
        # Length
        if data[12] != 0x32 and data[13] != 0x12:
            return False

        if data[14] != 0x03:
            return False

        if data[19] != crc(data, 1, len(data) - 3):
            return False

        if data[20] != 0x03:
            return False
        
        return True
    
    def decode_get_task_response(self, data : bytearray) -> TaskInformation:
        
        self.decode_response_template(data)
        from datetime import datetime, timezone
        
        if data[12] != 0x52 and data[13] != 0x12:
            return False
        
        if data[14] != 0x05:
            return False
        
        if data[17] != 0x13:
            return False
        if data[18] != 0x00:
            return False
        
        unixtimestamp = int.from_bytes(data[19:23], byteorder='little', signed=False)
        dt_start_time = datetime.fromtimestamp(unixtimestamp, tz=timezone.utc) # The mower does not have a timezone and therefore utc must be used for parsing
        
        duration = int.from_bytes(data[23:27], byteorder='little', signed=False)
        
        use_monday = data[27] == 0x01
        use_tuesday = data[28] == 0x01
        use_wednesday = data[29] == 0x01
        use_thursday = data[30] == 0x01
        use_friday = data[31] == 0x01
        use_saturday = data[32] == 0x01
        use_sunday = data[33] == 0x01
        
        return TaskInformation(next_start_time=dt_start_time, duration_in_seconds=duration,
                               on_monday=use_monday,
                               on_tuesday=use_tuesday,
                               on_wednesday=use_wednesday,
                               on_thursday=use_thursday,
                               on_friday=use_friday,
                               on_saturday=use_saturday,
                               on_sunday=use_sunday)
        


class TestStringMethods(unittest.TestCase):
    def test_decode_response_device_type(self):
        response = MowerResponse(1197489078)
        decoded = response.decode_response_device_type(
                bytearray.fromhex("02fd1300b63b604701e601af5a1209000002001701c803")
            )
        
        self.assertEqual(
            decoded.name,
            "305",
        )
        self.assertTrue(decoded.is_husqvarna)
        
        decoded = response.decode_response_device_type(
                bytearray.fromhex("02fd130038e38f0b01dc01af5a1209000002000c005903")
            )
        self.assertEqual(
            decoded.name,
            "315",
        )
        self.assertTrue(decoded.is_husqvarna)
        
    def test_decode_response_device_type_non_husqvarna(self):
        response = MowerResponse(0x5798CA1A)
        decoded = response.decode_response_device_type(
                bytearray.fromhex("02fd13005314a513012e01af5a1209000002001d02cd03")
            )
        self.assertEqual(
            decoded.name,
            "Minimo",
        )
        self.assertFalse(decoded.is_husqvarna)

    def test_decode_response_is_charging(self):
        response = MowerResponse(1197489078)

        self.assertEqual(
            response.decode_response_is_charging(
                bytearray.fromhex("02fd1200b63b604701db01af0a101500000100011603")
            ),
            True,
        )
        self.assertEqual(
            response.decode_response_is_charging(
                bytearray.fromhex("02fd1200b63b604701db01af0a101500000100004803")
            ),
            False,
        )

    def test_decode_response_mower_state(self):
        response = MowerResponse(1197489078)

        self.assertEqual(
            response.decode_response_mower_state(
                bytearray.fromhex("02fd1200b33b6047010901afea110100000100008103")
            ),
            "unknown",
        )

        response = MowerResponse(876143061)

        self.assertEqual(
            response.decode_response_mower_state(
                bytearray.fromhex("02fd1200d5e13834012301afea110200000100033a03")
            ),
            "error",
        )

    def test_decode_response_mower_activity(self):
        response = MowerResponse(1197489078)

        self.assertEqual(
            response.decode_response_mower_activity(
                bytearray.fromhex("02fd1200b33b6047010901afea110200000100026403")
            ),
            "goingOut",
        )
        
    def test_decode_get_number_of_tasks_response(self):
        response= MowerResponse(0x13a51453)
        self.assertEqual(
            response.decode_get_number_of_tasks_response(
                bytearray.fromhex("02fd150025be246a012e01af52120400000400010000004f03")
            ),
            1,
        )
        
    def test_decode_get_task_response(self):
        response= MowerResponse(0x13a51453)
        decoded = response.decode_get_task_response(
                bytearray.fromhex("02fd240025be246a010701af5212050000130000e100003831000001000101000101000000003003")
            )
        self.assertEqual(
            decoded.duration_in_seconds,
            12600,
        )
        self.assertTrue(decoded.on_monday)
        self.assertFalse(decoded.on_tuesday)
        self.assertTrue(decoded.on_wednesday)
        self.assertTrue(decoded.on_thursday)
        self.assertTrue(decoded.on_monday)
        self.assertFalse(decoded.on_friday)
        self.assertTrue(decoded.on_saturday)
        self.assertTrue(decoded.on_sunday)
        
        


if __name__ == "__main__":
    unittest.main()
