 /*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "get_batch_download_cloud_resources_status_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {
using namespace std;
using namespace OHOS::DataShare;
// LCOV_EXCL_START
bool GetBatchDownloadCloudResourcesStatusReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = DataSharePredicates::Unmarshal(this->predicates, parcel);
    return status;
}

bool GetBatchDownloadCloudResourcesStatusReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = DataSharePredicates::Marshal(this->predicates, parcel);
    return status;
}

std::string GetBatchDownloadCloudResourcesStatusReqBody::ToString() const
{
    std::stringstream ss;
    return ss.str();
}

bool GetBatchDownloadCloudResourcesStatusRespBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = ITypesUtil::Unmarshalling(this->downloadResourcesStatus, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetBatchDownloadCloudResourcesStatusRespBody::Marshalling(MessageParcel &parcel) const
{
    bool status = ITypesUtil::Marshalling(this->downloadResourcesStatus, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

std::string GetBatchDownloadCloudResourcesStatusRespBody::ToString() const
{
    std::stringstream ss;
    ss << "{\"downloadTaskStatus\": [";
    for (uint32_t i = 0; i < downloadResourcesStatus.size(); ++i) {
        ss << "\"" << downloadResourcesStatus[i] << "\"";
        if (i != downloadResourcesStatus.size() - 1) {
            ss << ",";
        }
    }
    ss << "]}";
    return ss.str();
}
// LCOV_EXCL_STOP
};