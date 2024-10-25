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
#include "v1_0/iusb_interface.h"

#define MTP_SEND_FILE              _IOW('M', 0, struct MtpFileRange)
/*
 * Receives data from the host and writes it to a file.
 * The file is created if it does not exist.
 */
#define MTP_RECEIVE_FILE           _IOW('M', 1, struct MtpFileRange)
/* Sends an event to the host via the interrupt endpoint */
#define MTP_SEND_EVENT             _IOW('M', 3, struct EventMtp)
/*
 * Sends the specified file range to the host,
 * with a 12 byte MTP data packet header at the beginning.
 */
#define MTP_SEND_FILE_WITH_HEADER  _IOW('M', 4, struct MtpFileRange)

using namespace std;
using namespace OHOS::HDI::Usb::Gadget::Mtp::V1_0;
namespace OHOS {
namespace Media {
const int READ_SIZE = 10240;

MtpDriver::MtpDriver()
{
}

MtpDriver::~MtpDriver()
{
}

int MtpDriver::OpenDriver()
{
    usbfnMtpInterface = IUsbfnMtpInterface::Get();
    if (usbfnMtpInterface == nullptr) {
        MEDIA_ERR_LOG("IUsbfnMtpInterface::Get() failed.");
        return E_ERR;
    }

    auto ret = usbfnMtpInterface->Start();
    if (ret != 0) {
        MEDIA_ERR_LOG("MtpDriver::OpenDriver Start() failed error = %{public}d", ret);
        return ret;
    }
    usbOpenFlag = true;
    return MTP_SUCCESS;
}

int MtpDriver::CloseDriver()
{
    if (usbfnMtpInterface != nullptr) {
        auto ret = usbfnMtpInterface->Stop();
        MEDIA_ERR_LOG("MtpDriver::CloseDriver Error: %{public}d", ret);
    }

    usbOpenFlag = false;
    return MTP_SUCCESS;
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
    auto ret = usbfnMtpInterface->Read(outBuffer);
    if (ret != 0) {
        outBuffer.resize(0);
        outReadSize = 0;
        MEDIA_ERR_LOG("MtpDriver::Read Out Error: %{public}d", ret);
        return E_ERR;
    }
    outReadSize = outBuffer.size();
    return MTP_SUCCESS;
}

void MtpDriver::Write(std::vector<uint8_t> &buffer, uint32_t &bufferSize)
{
    auto ret = usbfnMtpInterface->Write(buffer);
    bufferSize = static_cast<uint32_t>(ret);
}

int MtpDriver::ReceiveObj(MtpFileRange &mfr)
{
    struct UsbFnMtpFileSlice mfs = {
        .fd = mfr.fd,
        .offset = mfr.offset,
        .length = mfr.length,
        .command = mfr.command,
        .transactionId = mfr.transaction_id,
    };
    return usbfnMtpInterface->ReceiveFile(mfs);
}

int MtpDriver::SendObj(MtpFileRange &mfr)
{
    struct UsbFnMtpFileSlice mfs = {
        .fd = mfr.fd,
        .offset = 0,
        .length = mfr.length,
        .command = mfr.command,
        .transactionId = mfr.transaction_id,
    };
    return usbfnMtpInterface->SendFile(mfs);
}

int MtpDriver::WriteEvent(EventMtp &em)
{
    return usbfnMtpInterface->SendEvent(em.data);
}
} // namespace Media
} // namespace OHOS