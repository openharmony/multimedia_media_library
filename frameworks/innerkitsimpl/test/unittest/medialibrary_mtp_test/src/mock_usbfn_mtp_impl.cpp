/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "media_log.h"
#include "mock_usbfn_mtp_impl.h"

namespace OHOS {
namespace Media {
int32_t MockUsbfnMtpImpl::Init()
{
    return HDF_SUCCESS;
}

int32_t MockUsbfnMtpImpl::Release()
{
    return HDF_SUCCESS;
}

int32_t MockUsbfnMtpImpl::Start()
{
    return HDF_SUCCESS;
}

int32_t MockUsbfnMtpImpl::Stop()
{
    return HDF_SUCCESS;
}

int32_t MockUsbfnMtpImpl::Read(std::vector<uint8_t> &data)
{
    MEDIA_INFO_LOG("%{public}s: Read", __func__);
    return HDF_SUCCESS;
}

int32_t MockUsbfnMtpImpl::Write(const std::vector<uint8_t> &data)
{
    MEDIA_INFO_LOG("%{public}s: Write", __func__);
    sleep(1);
    return HDF_FAILURE;
}

int32_t MockUsbfnMtpImpl::ReceiveFile(const HDI::Usb::Gadget::Mtp::V1_0::UsbFnMtpFileSlice &mfs)
{
    return HDF_SUCCESS;
}

int32_t MockUsbfnMtpImpl::SendFile(const HDI::Usb::Gadget::Mtp::V1_0::UsbFnMtpFileSlice &mfs)
{
    return HDF_SUCCESS;
}

int32_t MockUsbfnMtpImpl::SendEvent(const std::vector<uint8_t> &eventData)
{
    MEDIA_INFO_LOG("%{public}s: SendEvent", __func__);
    sleep(1);
    return HDF_FAILURE;
}

} // namespace Media
} // namespace OHOS
