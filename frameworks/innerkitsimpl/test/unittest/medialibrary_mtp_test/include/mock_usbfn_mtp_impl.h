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

#ifndef FRAMEWORKS_INNERKITSIMPL_TEST_UNITTEST_MEDIALIBRARY_TEST_INCLUDE_MOCK_USB_TEST_H_
#define FRAMEWORKS_INNERKITSIMPL_TEST_UNITTEST_MEDIALIBRARY_TEST_INCLUDE_MOCK_USB_TEST_H_


#include "v1_0/iusbfn_mtp_interface.h"

#include <gmock/gmock.h>

namespace OHOS {
namespace Media {
class MockUsbfnMtpImpl : public HDI::Usb::Gadget::Mtp::V1_0::IUsbfnMtpInterface {
public:
    MockUsbfnMtpImpl() = default;
    virtual ~MockUsbfnMtpImpl() = default;

    int32_t Start() override;
    int32_t Stop() override;
    int32_t Read(std::vector<uint8_t> &data) override;
    int32_t Write(const std::vector<uint8_t> &data) override;
    int32_t ReceiveFile(const HDI::Usb::Gadget::Mtp::V1_0::UsbFnMtpFileSlice &mfs) override;
    int32_t SendFile(const HDI::Usb::Gadget::Mtp::V1_0::UsbFnMtpFileSlice &mfs) override;
    int32_t SendEvent(const std::vector<uint8_t> &eventData) override;

    int32_t Init() override;
    int32_t Release() override;
};
} // namespace V1_0
} // namespace Mtp

#endif // FRAMEWORKS_INNERKITSIMPL_TEST_UNITTEST_MEDIALIBRARY_TEST_INCLUDE_MOCK_USB_TEST_H_
