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
#include "payload_data/object_event_data.h"
#include "media_log.h"
#include "media_mtp_utils.h"
#include "mtp_packet_tools.h"
using namespace std;

namespace OHOS {
namespace Media {
ObjectEventData::ObjectEventData(shared_ptr<MtpOperationContext> &context) : PayloadData(context)
{
}

ObjectEventData::ObjectEventData()
{
}

ObjectEventData::~ObjectEventData()
{
}

int ObjectEventData::Parser(const vector<uint8_t> &buffer, uint32_t readSize)
{
    return MTP_SUCCESS;
}

int ObjectEventData::Maker(vector<uint8_t> &outBuffer)
{
    uint32_t length = MTP_CONTAINER_HEADER_SIZE + sizeof(payload_);
    MtpPacketTool::PutUInt32(outBuffer, length);
    MtpPacketTool::PutUInt32(outBuffer, payload_);
    return MTP_SUCCESS;
}

uint32_t ObjectEventData::CalculateSize()
{
    std::vector<uint8_t> tmpUse;
    int res = Maker(tmpUse);
    if (res != MTP_SUCCESS) {
        return res;
    }

    return tmpUse.size();
}

void ObjectEventData::SetPayload(const int32_t &payload)
{
    payload_ = payload;
}
} // namespace Media
} // namespace OHOS