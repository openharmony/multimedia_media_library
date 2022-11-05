/*
* Copyright (C) 2022 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "mtp_driver.h"
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_operation_utils.h"
#include "mtp_packet_tools.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <sys/ioctl.h>

#define MTP_SEND_FILE              _IOW('M', 0, struct MtpFileRange)
/*
 * Receives data from the host and writes it to a file.
 * The file is created if it does not exist.
 */
#define MTP_RECEIVE_FILE           _IOW('M', 1, struct MtpFileRange)
/* Sends an event to the host via the interrupt endpoint */
#define MTP_SEND_EVENT             _IOW('M', 3, struct mtp_event)
/*
 * Sends the specified file range to the host,
 * with a 12 byte MTP data packet header at the beginning.
 */
#define MTP_SEND_FILE_WITH_HEADER  _IOW('M', 4, struct MtpFileRange)
namespace OHOS {
namespace Media {
const int PORT = 02;
const int READ_SIZE = 10240;

MtpDriver::MtpDriver()
{
    usbOpenFlag = false;
}

MtpDriver::~MtpDriver()
{
}

int MtpDriver::OpenDriver()
{
    usbDriver = open("/dev/mtp_usb", PORT);
    if (usbDriver < 0) {
        MEDIA_ERR_LOG("can't open MtpDriver error = %{public}d", errno);
        return E_ERR;
    }
    usbOpenFlag = true;
    return MTP_SUCCESS;
}

int MtpDriver::CloseDriver()
{
    usbOpenFlag = false;
    return 0;
}

int MtpDriver::Read(std::vector<uint8_t> &outBuffer, uint32_t &outReadSize)
{
    if (usbOpenFlag == false) {
        int ret = OpenDriver();
        if (ret < 0) {
            return MTP_ERROR_DRIVER_OPEN_FAILED;
        }
    }
    if (outReadSize == 0) {
        outReadSize = READ_SIZE;
    }

    outBuffer.resize(outReadSize);
    auto len = read(usbDriver, outBuffer.data(), outReadSize);
    outBuffer.resize(len);
    outReadSize = len;
    return MTP_SUCCESS;
}

void MtpDriver::Write(std::vector<uint8_t> &buffer, uint32_t bufferSize)
{
    write(usbDriver, buffer.data(), bufferSize);
}

int MtpDriver::ReceiveObj(MtpFileRange &mfr)
{
    return ioctl(usbDriver, MTP_RECEIVE_FILE, reinterpret_cast<unsigned long>(&mfr));
}

int MtpDriver::SendObj(MtpFileRange &mfr)
{
    return ioctl(usbDriver, MTP_SEND_FILE_WITH_HEADER, reinterpret_cast<unsigned long>(&mfr));
}

int MtpDriver::WriteEvent(EventMtp &em)
{
    auto ret = ioctl(usbDriver, MTP_SEND_EVENT, reinterpret_cast<unsigned long>(&em));
    return ret;
}
} // namespace Media
} // namespace OHOS