/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include "analysis_data_manager.h"

#include "iservice_registry.h"
#include "media_log.h"
#include "user_inner_ipc_client.h"
#include "prepare_lcd_vo.h"
#include "remove_cloud_lcd_vo.h"
#include "medialibrary_business_code.h"

using namespace std;

namespace OHOS {
namespace Media::AnalysisData {
sptr<IRemoteObject> AnalysisDataManager::token_ = nullptr;
std::shared_ptr<DataShare::DataShareHelper> AnalysisDataManager::sDataShareHelper_ = nullptr;
constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
const std::string MEDIALIBRARY_DATA_URI = "datashare:///media";

// LCOV_EXCL_START
AnalysisDataManager &AnalysisDataManager::GetInstance()
{
    static AnalysisDataManager analysisMgr;
    return analysisMgr;
}
// LCOV_EXCL_STOP

AnalysisDataManager::AnalysisDataManager()
{
    token_ = InitToken();
    if (sDataShareHelper_ == nullptr && token_ != nullptr) {
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    }
}
 
sptr<IRemoteObject> AnalysisDataManager::InitToken()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(saManager != nullptr, nullptr, "get system ability mgr failed.");
    auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, nullptr, "GetSystemAbility Service failed.");
    return remoteObj;
}

int32_t AnalysisDataManager::PrepareLcd(const std::vector<int64_t> &fileIds, uint32_t netBearerBitmap,
                                        std::unordered_map<uint64_t, int32_t> &results)
{
    MEDIA_INFO_LOG("PrepareLcd called, fileIds.size()=%{public}zu, netBearerBitmap=%{public}u", fileIds.size(),
                   netBearerBitmap);
    PrepareLcdReqBody reqBody;
    PrepareLcdRespBody respBody;
    reqBody.fileIds = fileIds;
    reqBody.netBearerBitmap = netBearerBitmap;
    uint32_t operationCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_PREPARE_LCD);
    int32_t ret = IPC::UserInnerIPCClient()
                      .SetDataShareHelper(sDataShareHelper_)
                      .Post(operationCode, reqBody, respBody);
    if (ret == E_OK) {
        results = respBody.results;
        MEDIA_INFO_LOG("PrepareLcd success, ret=%{public}d, results.size()=%{public}zu", respBody.ret, results.size());
        ret = respBody.ret;
    } else {
        MEDIA_ERR_LOG("PrepareLcd failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t AnalysisDataManager::RemoveCloudLcd(const std::vector<int64_t> &fileIds)
{
    MEDIA_INFO_LOG("RemoveCloudLcd called, fileIds.size()=%{public}zu", fileIds.size());
    RemoveCloudLcdReqBody reqBody;
    reqBody.fileIds = fileIds;
    uint32_t operationCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_REMOVE_CLOUD_LCD);
    int32_t ret = IPC::UserInnerIPCClient()
                      .SetDataShareHelper(sDataShareHelper_)
                      .Post(operationCode, reqBody);
    if (ret == E_OK) {
        MEDIA_INFO_LOG("RemoveCloudLcd success, ret=%{public}d", ret);
    } else {
        MEDIA_ERR_LOG("RemoveCloudLcd failed, ret=%{public}d", ret);
    }
    return ret;
}
}
}