/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "DfxDeprecatedPermUsage"

#include "dfx_deprecated_perm_usage.h"

#include <charconv>

#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "media_log.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_errno.h"
#include "preferences_helper.h"

namespace OHOS {
namespace Media {
const std::string DFX_DEPRECATED_PERM_USAGE_XML = "/data/storage/el2/base/preferences/dfx_deprecated_perm_usage.xml";
constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";
const std::string OPERATION_OBJECT = "OPERATION_OBJECT";
const std::string OPERATION_TYPE = "OPERATION_TYPE";
const std::string BUNDLE_NAME_LIST = "BUNDLE_NAME_LIST";
const size_t BATCH_SIZE = 300;

std::mutex DfxDeprecatedPermUsage::mutex_;

int32_t DfxDeprecatedPermUsage::Record(const uint32_t object, const uint32_t type)
{
    std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
    CHECK_AND_RETURN_RET_WARN_LOG(lock.try_lock(), E_OK, "Record or statistics has started, skipping this operation");

    std::string bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    CHECK_AND_EXECUTE(!bundleName.empty(), bundleName = std::to_string(IPCSkeleton::GetCallingUid()));

    int32_t errCode = NativePreferences::E_OK;
    std::shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_DEPRECATED_PERM_USAGE_XML, errCode);
    CHECK_AND_RETURN_RET_LOG(prefs, E_ERR, "get preferences error: %{public}d", errCode);

    std::string key = std::to_string(object) + "," + std::to_string(type);
    std::vector<std::string> bundleNames = prefs->Get(key, std::vector<std::string>{});
    if (std::find(bundleNames.begin(), bundleNames.end(), bundleName) == bundleNames.end()) {
        bundleNames.push_back(bundleName);
        prefs->Put(key, bundleNames);
        prefs->FlushSync();
    }
    return E_OK;
}

static bool StrToUint32(const std::string &str, uint32_t &value)
{
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    return ec == std::errc{} && ptr == str.data() + str.size();
}

int32_t DfxDeprecatedPermUsage::Statistics()
{
    std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
    CHECK_AND_RETURN_RET_WARN_LOG(lock.try_lock(), E_OK, "Record or statistics has started, skipping this operation");

    int32_t errCode = NativePreferences::E_OK;
    std::shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_DEPRECATED_PERM_USAGE_XML, errCode);
    CHECK_AND_RETURN_RET_LOG(prefs, E_ERR, "get preferences error: %{public}d", errCode);

    std::unordered_map<std::string, NativePreferences::PreferencesValue> allDatas = prefs->GetAllDatas();
    CHECK_AND_RETURN_RET_INFO_LOG(!allDatas.empty(), E_OK, "has no data to statistics");

    MEDIA_INFO_LOG("Statistics start, allDatas size: %{public}zu", allDatas.size());
    int32_t reportResult = 0;
    for (const auto &[key, val] : allDatas) {
        size_t commaPos = key.find(",");
        CHECK_AND_CONTINUE_ERR_LOG(commaPos != std::string::npos, "invalid key format: %{public}s", key.c_str());
        std::string objectStr = key.substr(0, commaPos);
        std::string typeStr = key.substr(commaPos + 1);
        uint32_t object = 0;
        uint32_t type = 0;
        CHECK_AND_CONTINUE_ERR_LOG(StrToUint32(objectStr, object) && StrToUint32(typeStr, type),
            "object or type is invalid, key format: %{public}s",
            key.c_str());
        std::vector<std::string> bundleNames = val;
        CHECK_AND_CONTINUE_ERR_LOG(!bundleNames.empty(), "bundleNames is empty");
        int32_t batchResult = ReportBatch(object, type, bundleNames);
        if (batchResult != 0) {
            MEDIA_ERR_LOG("ReportBatch failed, error: %{public}d", batchResult);
            reportResult = batchResult;
        }
    }
    if (reportResult == 0) {
        prefs->Clear();
        prefs->FlushSync();
    }
    return E_OK;
}

int32_t DfxDeprecatedPermUsage::ReportBatch(
    const uint32_t object, const uint32_t type, const std::vector<std::string> &bundleNames)
{
    int32_t batchResult = 0;
    for (size_t start = 0; start < bundleNames.size(); start += BATCH_SIZE) {
        std::ostringstream oss;
        size_t end = std::min(start + BATCH_SIZE, bundleNames.size());
        oss << bundleNames[start];
        for (size_t i = start + 1; i < end; ++i) {
            oss << "," << bundleNames[i];
        }
        int32_t ret = Report(object, type, oss.str());
        if (ret != 0) {
            MEDIA_ERR_LOG("Report failed, error: %{public}d", ret);
            batchResult = ret;
        }
    }
    return batchResult;
}

int32_t DfxDeprecatedPermUsage::Report(const uint32_t object, const uint32_t type, const std::string &bundleNameList)
{
    int32_t ret = HiSysEventWrite(
        MEDIA_LIBRARY,
        "MEDIALIB_DEPRECATED_PERM_USAGE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        OPERATION_OBJECT, object,
        OPERATION_TYPE, type,
        BUNDLE_NAME_LIST, bundleNameList);

    CHECK_AND_RETURN_RET_LOG(ret == 0, ret, "Deprecated perm usage statistics report error: %{public}d", ret);
    MEDIA_INFO_LOG("Deprecated perm usage statistics report success");
    return ret;
}
}  // namespace Media
}  // namespace OHOS