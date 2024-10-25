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
#include "mtp_event.h"
#include <numeric>
#include <unistd.h>
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_packet.h"
#include "mtp_packet_tools.h"
using namespace std;
namespace OHOS {
namespace Media {
MtpEvent::MtpEvent(const std::shared_ptr<MtpOperationContext> &context)
{
    if (context != nullptr) {
        mtpContextPtr_ = context;
    }
}

MtpEvent::~MtpEvent()
{
}

void MtpEvent::SendObjectAdded(const std::string &path)
{
    handleptr_ = make_shared<MtpOperationUtils>(mtpContextPtr_);
    uint32_t handle{0};
    int i{0};
    while (i < MTP_SEND_ADD_TIMES) {
        if (handleptr_->GetHandleByPaths(path, handle) == E_SUCCESS) {
            mtpContextPtr_->eventHandle = handle;
            SendEvent(MTP_EVENT_OBJECT_ADDED_CODE);
            return;
        }
        i++;
        usleep(MTP_SEND_ADD);
        MEDIA_DEBUG_LOG("MtpEvent::sendObjectAdded try %{public}d times", i);
    }
}

void MtpEvent::SendObjectRemoved(const std::string &path)
{
    handleptr_ = make_shared<MtpOperationUtils>(mtpContextPtr_);
    uint32_t handle{0};
    int i{0};
    while (i < MTP_SEND_ADD_TIMES) {
        if (handleptr_->GetHandleByPaths(path, handle) == E_SUCCESS) {
            mtpContextPtr_->eventHandle = handle;
            SendEvent(MTP_EVENT_OBJECT_REMOVED_CODE);
            return;
        }
        i++;
        usleep(MTP_SEND_ADD);
        MEDIA_DEBUG_LOG("MtpEvent::sendObjectRemoved try %{public}d times", i);
    }
}

void MtpEvent::SendObjectInfoChanged(const std::string &path)
{
    handleptr_ = make_shared<MtpOperationUtils>(mtpContextPtr_);
    uint32_t handle{0};
    int i{0};
    while (i < MTP_SEND_ADD_TIMES) {
        if (handleptr_->GetHandleByPaths(path, handle) == E_SUCCESS) {
            mtpContextPtr_->eventHandle = handle;
            SendEvent(MTP_EVENT_OBJECT_INFO_CHANGED_CODE);
            return;
        }
        i++;
        usleep(MTP_SEND_ADD);
        MEDIA_DEBUG_LOG("MtpEvent::sendObjectInfoChanged try %{public}d times", i);
    }
}

void MtpEvent::SendDevicePropertyChanged()
{
    mtpContextPtr_->eventProperty = MTP_DEVICE_PROPERTY_BATTERY_LEVEL_CODE;
    SendEvent(MTP_EVENT_DEVICE_PROP_CHANGED_CODE);
}

void MtpEvent::SendEvent(const int32_t &code)
{
    shared_ptr<PayloadData> eventPayloadData;

    uint16_t responseCode = EventPayloadData(code, eventPayloadData);
    if (responseCode == MTP_UNDEFINED_CODE) {
        MEDIA_DEBUG_LOG("Mtp Event GetPayloadData Error");
    }
    shared_ptr<HeaderData> eventHeaderData =
        make_shared<HeaderData>(EVENT_CONTAINER_TYPE, code, HeaderData::sTransactionID_);
    shared_ptr<MtpPacket> eventPacketPtr = std::make_shared<MtpPacket>(mtpContextPtr_, mtpContextPtr_->mtpDriver);
    eventPacketPtr->Init(eventHeaderData, eventPayloadData);
    int errorCode = eventPacketPtr->Maker(true);
    if (errorCode != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpEvent::SendEvent  responsePacket Maker err: %{public}d", errorCode);
        return;
    }
    errorCode = eventPacketPtr->Write();
    if (errorCode != MTP_SUCCESS) {
        MEDIA_ERR_LOG("MtpEvent::SendEvent responsePacket Write err: %{public}d", errorCode);
        return;
    }
}

uint16_t MtpEvent::EventPayloadData(const uint16_t code, shared_ptr<PayloadData> &data)
{
    uint16_t responseCode = MTP_UNDEFINED_CODE;
    if (handleptr_ == nullptr) {
        handleptr_ = make_shared<MtpOperationUtils>(mtpContextPtr_);
    }
    switch (code) {
        case MTP_EVENT_OBJECT_ADDED_CODE:
        case MTP_EVENT_OBJECT_REMOVED_CODE:
        case MTP_EVENT_OBJECT_INFO_CHANGED_CODE:
            responseCode = handleptr_->ObjectEvent(data, mtpContextPtr_->eventHandle);
            break;
        case MTP_EVENT_DEVICE_PROP_CHANGED_CODE:
            responseCode = handleptr_->ObjectEvent(data, mtpContextPtr_->eventProperty);
            break;
        default:
            break;
    }
    return responseCode;
}
} // namespace Media
} // namespace OHOS