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
#include "acquire_debug_database_vo.h"

#include "media_log.h"

namespace OHOS::Media {

bool AcquireDebugDatabaseReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->betaIssueId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->betaScenario);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool AcquireDebugDatabaseReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->betaIssueId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->betaScenario);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool AcquireDebugDatabaseRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->fileName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->fileSize);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool AcquireDebugDatabaseRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->fileName);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->fileSize);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
}  // namespace OHOS::Media