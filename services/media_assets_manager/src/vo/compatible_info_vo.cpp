/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaGetResultSetFromDbVo"

#include "compatible_info_vo.h"

#include <sstream>

#include "itypes_util.h"
#include "media_log.h"

namespace OHOS::Media {
using namespace std;
bool SetCompatibleInfoReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadBool(this->supportedHighResolution);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->supportedMimeTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool SetCompatibleInfoReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteBool(this->supportedHighResolution);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->supportedMimeTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetCompatibleInfoReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetCompatibleInfoReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetCompatibleInfoRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadBool(this->supportedHighResolution);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->supportedMimeTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetCompatibleInfoRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteBool(this->supportedHighResolution);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->supportedMimeTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetTranscodeCheckInfoReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetTranscodeCheckInfoReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetTranscodeCheckInfoRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadBool(this->supportedHighResolution);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->supportedMimeTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadInt32(this->preferredCompatibleMode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetTranscodeCheckInfoRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->bundleName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteBool(this->supportedHighResolution);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling(this->supportedMimeTypes, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteInt32(this->preferredCompatibleMode);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
}