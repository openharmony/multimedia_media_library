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
 
#define MLOG_TAG "SettingsDataManager"

#include "settings_data_manager.h"

#include <memory>

#include "datashare_helper.h"
#include "datashare_errno.h"
#include "datashare_result_set.h"
#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS::Media {
inline static const std::string SETTING_DATA_QUERY_URI = "datashareproxy://";
inline static const std::string SETTING_DATA_COMMON_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
inline static const std::string PHOTOS_SYNC_SWITCH_KEY = "photos_sync_options";

class MediaSettingDataHelper {
public:
    MediaSettingDataHelper()
    {
        DataShare::CreateOptions options;
        options.enabled_ = true;
        dataShareHelper_ = DataShare::DataShareHelper::Creator(SETTING_DATA_QUERY_URI, options);
        if (dataShareHelper_ == nullptr) {
            MEDIA_ERR_LOG("dataShareHelper = nullptr");
            return;
        }
    }

    ~MediaSettingDataHelper()
    {
        if (dataShareHelper_) {
            if (!dataShareHelper_->Release()) {
                MEDIA_INFO_LOG("Release set data share helper failed");
                return;
            }
        }
    }

    explicit operator bool() const noexcept
    {
        return dataShareHelper_ == nullptr ? false : true;
    }

    DataShare::DataShareHelper& operator*() const
    {
        return *dataShareHelper_;
    }

    DataShare::DataShareHelper* operator->() const noexcept
    {
        return dataShareHelper_.get();
    }

private:
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
};

static SwitchStatus StringToSwitchStatus(const std::string& value)
{
    static const std::unordered_map<std::string, SwitchStatus> STRING_SWITCH_STATUS_MAP = {
        { std::to_string(static_cast<int>(SwitchStatus::CLOSE)), SwitchStatus::CLOSE },
        { std::to_string(static_cast<int>(SwitchStatus::CLOUD)), SwitchStatus::CLOUD },
        { std::to_string(static_cast<int>(SwitchStatus::HDC)), SwitchStatus::HDC },
    };
    CHECK_AND_RETURN_RET_LOG(STRING_SWITCH_STATUS_MAP.count(value), SwitchStatus::NONE,
        "invalid SwitchStatus: %{public}s", value.c_str());
    return STRING_SWITCH_STATUS_MAP.at(value);
}

SwitchStatus SettingsDataManager::GetPhotosSyncSwitchStatus()
{
    std::string value;
    auto ret = QueryParamInSettingData(PHOTOS_SYNC_SWITCH_KEY, value);
    if (ret != E_OK) {
        return SwitchStatus::NONE;
    }
    return StringToSwitchStatus(value);
}

int32_t SettingsDataManager::QueryParamInSettingData(const std::string &key, std::string &value)
{
    MediaSettingDataHelper dataShareHelper;
    if (!dataShareHelper) {
        return E_DB_FAIL;
    }

    MEDIA_INFO_LOG("Query key: %{public}s", key.c_str());
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("KEYWORD", key);
    std::vector<std::string> columns = {"value"};
    std::string queryUri = SETTING_DATA_COMMON_URI + "&key=" + key;
    Uri uri(queryUri);

    std::shared_ptr<DataShare::DataShareResultSet> resultSet = dataShareHelper->Query(uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_DB_FAIL, "resultSet == nullptr");
    auto ret = resultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == DataShare::E_OK, ret, "GoToFirstRow failed, err: %{public}d", ret);

    int32_t columnIndex = 0;
    ret = resultSet->GetColumnIndex("value", columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == DataShare::E_OK, ret, "GetColumnIndex failed, err: %{public}d", ret);
    ret = resultSet->GetString(columnIndex, value);
    CHECK_AND_RETURN_RET_LOG(ret == DataShare::E_OK, ret, "GetString failed, err: %{public}d", ret);
    MEDIA_INFO_LOG("Query success, value: %{public}s", value.c_str());
    return E_OK;
}
}