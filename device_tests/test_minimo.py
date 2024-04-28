

import argparse
import asyncio
import coloredlogs, logging

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from datetime import datetime, timezone
import sys
sys.path.append('../')

from automower_ble.mower import Mower

logger = logging.getLogger(__name__)


logging.getLogger('bleak.backends.bluezdbus.client').setLevel(logging.INFO)
logging.getLogger('bleak.backends.bluezdbus.manager').setLevel(logging.INFO)
#logging.getLogger('automower_ble.mower').setLevel(logging.DEBUG)

coloredlogs.install(level='DEBUG', logger=logger)
# log_level = logging.DEBUG
# logging.basicConfig(
#     level=log_level,
#     format="%(asctime)-15s %(name)-8s %(levelname)s: %(message)s",
# )


async def main(mower:Mower, must_start:bool = False, must_stop:bool = False):
    device = None
    try:
            
        logger.info('Start test mower')
        device = await BleakScanner.find_device_by_address(mower.address)
        if device is None:
            print("Unable to connect to device address: " + mower.address)
            print("Please make sure the device address is correct, the device is powered on and nearby")
            return
        logger.info(f'Device found. Start connecting to device {mower.address}')
        await mower.connect(device)
        logger.info(f'Connected to device with address {mower.address}')
        logger.info(f'Mower : {mower}')

        model = await mower.get_model()
        logger.info(f'Model : {model.name} -> is_husqvarna : {model.is_husqvarna}')

        logger.info('Start sending keep Alive')
        keepalive_response = await mower.send_keepalive()
        if not keepalive_response:
            logger.error(f'Error sending keepalive request {keepalive_response}')

        enterOperatorPinRequestResult = await mower.send_operator_pin_request(1331)
        logger.debug(f'Enter Operator Pin Request Result {enterOperatorPinRequestResult}')


        success = await mower.getStartupSequenceRequiredRequest()
        logger.debug(f'Startupsequence is required response {success}')

        operator_is_logged_in = await mower.is_operator_loggedin()
        logger.debug(f'Operator is logged in {operator_is_logged_in}')

        activity = await mower.mower_activity()
        logger.debug(f'Mower activity : {activity}')

        mode= await mower.get_mode()
        logger.debug(f'Mower mode : {mode}')

        serial_number = await mower.get_serial_number()
        logger.debug(f'Serial number : {serial_number}')

        restriction_reason = await mower.get_restriction_reason()
        logger.debug(f'Restriction Reason : {restriction_reason}')

        next_start_time = await mower.mower_next_start_time()
        if next_start_time:
            dt_start_time = datetime.fromtimestamp(next_start_time, tz=timezone.utc) # The mower does not have a timezone and therefore utc must be used for parsing
            logger.debug("Next start time: " + dt_start_time.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            logger.debug("No next start time")

        number_of_tasks = await mower.get_number_of_tasks()
        logger.debug(f'number of tasks : {number_of_tasks}')

        # TODO: implement get task functioality
        # for now : don't know how to parse "task number"
        task_number = 4
        logger.debug(f'Start requesting task {task_number}')
        task_response = await mower.get_task(task_number)
        logger.debug(f'Next task starts at {task_response.next_start_time.strftime("%H:%M:%S")}')
        
        
        keepalive_response = await mower.send_keepalive()

        mower_state = await mower.mower_state(model.is_husqvarna)
        logger.debug(f'Mower state response {mower_state}')

        mower_activity = await mower.mower_activity()
        logger.debug(f'Mower activity : {mower_activity}')

        get_mode_response = await mower.get_mode()
        logger.debug(f'Mode : {get_mode_response}')

        next_start_time = await mower.mower_next_start_time()
        logger.debug(f'Next Start Time : {next_start_time}')
        if next_start_time:
            dt_start_time = datetime.fromtimestamp(next_start_time, tz=timezone.utc) # The mower does not have a timezone and therefore utc must be used for parsing
            logger.debug("Next start time: " + dt_start_time.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            logger.debug("No next start time")

        restriction_reason = await mower.get_restriction_reason()
        logger.debug(f'Restriction reason : {restriction_reason}')

        if must_start:
            # actually start mowing for 30 minutes

            logger.debug('--------------')
            logger.debug('start setting mode to manual')
            await mower.set_mode_of_operation("manual")
            logger.debug('Mode of operation set to manual')
            logger.debug('--------------')


            logger.debug(f'Overriding mow to 30 mins')
            override_mow_response = await mower.set_override_mow(30) # 30 minutes override mow
            logger.debug(f'override mow response : {override_mow_response}')
            logger.debug('--------------')


            start_trigger = await mower.start_trigger_request()
            logger.debug(f'Start trigger response : {start_trigger}')
            
        if must_stop:
            logger.debug(f'Must stop mowing. Send Park command to mower')
            await mower.set_mode_of_operation('manual')
            logger.debug('Finished setting mode of operation to manual. Sending park command')
            await mower.mower_park()
            logger.debug('Finished sending park command')
            start_trigger = await mower.start_trigger_request()
            logger.debug(f'Start trigger response : {start_trigger}')

        keepalive_response = await mower.send_keepalive()

        mower_state = await mower.mower_state(model.is_husqvarna)
        logger.debug(f'Mower state response {mower_state}')

        mower_activity = await mower.mower_activity()
        logger.debug(f'Mower activity : {mower_activity}')

        logger.info('Finished testing mower')
        
        
    except Exception as e:
        logger.error(f'There was an issue communicating with the device')
        raise e
        
    finally:
        if not device is None:
            await mower.disconnect()
        logger.info('Disconnected from Mower')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    device_group = parser.add_mutually_exclusive_group(required=False)

    parser.add_argument(
        "-a",
        "--address",
        metavar="<address>",
        help="the Bluetooth address of the Automower device to connect to",
        default="d8:71:4d:7c:7a:36",
        required=False
    )
    
    device_group.add_argument(
        '--start', action='store_true', help="start mowing"
    )
    device_group.add_argument(
        '--stop', action='store_true', help='stop mowing'
    )

    args = parser.parse_args()

    if args.start and not args.stop:
        logger.info('Must start mowing')
    if args.stop and not args.start:
        logger.info('Must stop mowing')
    
    if args.start and args.stop:
        logger.error('There is an issue. You cannot start and stop both at the same time')

    mower = Mower(0x13a51453, args.address)

    asyncio.run(main(mower, must_start = args.start, must_stop = args.stop))