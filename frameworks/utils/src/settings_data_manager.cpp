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
#include "iservice_registry.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_uri_utils.h"
#ifdef MEDIA_LIBRARY_MEMOSPACE_SERVICE_SUPPORT
#include "hdc_device_id.h"
#endif

namespace OHOS::Media {
inline static const std::string SETTING_DATA_QUERY_URI = "datashareproxy://";
inline static const std::string SETTING_DATA_COMMON_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
inline static const std::string PHOTOS_USER_PROPERTY_INIT_URI =
    "datashare:///com.huawei.hmos.photos.provider.userPropertySettings?init";
inline static const std::string PHOTOS_SYNC_SWITCH_KEY = "photos_sync_options";
inline static const std::string PHOTOS_USER_PROPERTY_URI =
    "datashare:///com.huawei.hmos.photos.provider.userPropertySettings";
inline static const std::string PHOTOS_SYNC_SWITCH_USER_KEY = "photos_sync_options_user";
inline static const std::string ALL_PHOTOS_ALBUM_UPLOAD_USER = "photos_all_album_upload_user";
inline static const std::string ALL_PHOTOS_ALBUM_UPLOAD = "photos_all_album_upload";
inline static const std::string ALL_PHOTOS_ALBUM_UPLOAD_OFF = "0";
static constexpr int32_t BASE_USER_RANGE = 200000;
constexpr int PHOTOS_STORAGE_MANAGER_ID = 5003;

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

static int32_t GetUserId()
{
    int32_t uid = static_cast<int32_t>(getuid());
    return uid / BASE_USER_RANGE;
}

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

std::optional<SwitchStatus> SettingsDataManager::GetPhotosSyncSwitchUserStatus()
{
    std::string value;
    auto ret = QueryParamInSettingData(PHOTOS_SYNC_SWITCH_USER_KEY, value);
    if (ret == E_OK) {
        return std::optional<SwitchStatus>(StringToSwitchStatus(value));
    }
    return std::nullopt;
}

SwitchStatus SettingsDataManager::GetPhotosSyncSwitchStatus()
{
    auto status = GetPhotosSyncSwitchUserStatus();
    if (status.has_value()) {
        return status.value();
    }

    MEDIA_INFO_LOG("query user sync switch failed, notify photos init");
    int32_t notifyRet = NotifyPhotosSyncSwitchInitByUpdate();
    if (notifyRet == E_OK) {
        status = GetPhotosSyncSwitchUserStatus();
        if (status.has_value()) {
            return status.value();
        }
        MEDIA_WARN_LOG("query user sync switch after init still failed");
    } else {
        MEDIA_WARN_LOG("notify photos init by datashare update failed, ret: %{public}d", notifyRet);
    }
    return GetPhotosSyncSwitchDeviceStatus();
}

static int32_t QueryParamInDeviceSettingData(const std::string &key, std::string &value)
{
    MediaSettingDataHelper dataShareHelper;
    if (!dataShareHelper) {
        MEDIA_ERR_LOG("failed to init dataShareHelper");
        return E_DB_FAIL;
    }

    MEDIA_DEBUG_LOG("Query key: %{public}s", key.c_str());
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
    MEDIA_DEBUG_LOG("Query success, value: %{public}s", value.c_str());
    return E_OK;
}

static int32_t UpdateParamInDeviceSettingData(const std::string &key, const std::string &value)
{
    MediaSettingDataHelper dataShareHelper;
    if (!dataShareHelper) {
        MEDIA_ERR_LOG("failed to init dataShareHelper");
        return E_DB_FAIL;
    }

    MEDIA_INFO_LOG("Update device key: %{public}s", key.c_str());
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("KEYWORD", key);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put("VALUE", value);

    std::string updateUri = SETTING_DATA_COMMON_URI + "&key=" + key;
    Uri uri(updateUri);
    auto ret = dataShareHelper->UpdateEx(uri, predicates, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(ret.first == DataShare::E_OK, ret.first,
        "update device key failed, err: %{public}d", ret.first);
    return ret.first;
}

static int32_t InsertParamInDeviceSettingData(const std::string &key, const std::string &value)
{
    MediaSettingDataHelper dataShareHelper;
    if (!dataShareHelper) {
        MEDIA_ERR_LOG("failed to init dataShareHelper");
        return E_DB_FAIL;
    }

    MEDIA_INFO_LOG("Insert device key: %{public}s", key.c_str());
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put("KEYWORD", key);
    valuesBucket.Put("VALUE", value);

    std::string insertUri = SETTING_DATA_COMMON_URI + "&key=" + key;
    Uri uri(insertUri);
    auto ret = dataShareHelper->InsertEx(uri, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(ret.first == DataShare::E_OK, ret.first,
        "insert device key failed, return: %{public}d", ret.first);
    return ret.first;
}

SwitchStatus SettingsDataManager::GetPhotosSyncSwitchDeviceStatus()
{
    std::string value;
    auto ret = QueryParamInDeviceSettingData(PHOTOS_SYNC_SWITCH_KEY, value);
    if (ret != E_OK) {
        return SwitchStatus::NONE;
    }
    return StringToSwitchStatus(value);
}

int32_t SettingsDataManager::NotifyPhotosSyncSwitchInitByUpdate()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Samgr is nullptr");
        return E_DB_FAIL;
    }

    auto object = samgr->GetSystemAbility(PHOTOS_STORAGE_MANAGER_ID);
    if (object == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility failed");
        return E_DB_FAIL;
    }

    auto dataShareHelper = DataShare::DataShareHelper::Creator(object, PHOTOS_USER_PROPERTY_URI);
    if (dataShareHelper == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper = nullptr");
        return E_DB_FAIL;
    }

    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject valueObject(1);
    valuesBucket.Put("init", valueObject);
    Uri uri(PHOTOS_USER_PROPERTY_INIT_URI);
    auto ret = dataShareHelper->UpdateEx(uri, predicates, valuesBucket);
    dataShareHelper->Release();
    CHECK_AND_RETURN_RET_LOG(ret.first == DataShare::E_OK, ret.first,
        "notify photos init failed, err: %{public}d", ret.first);
    return E_OK;
}

int32_t SettingsDataManager::QueryParamInSettingData(const std::string &key, std::string &value)
{
    MediaSettingDataHelper dataShareHelper;
    if (!dataShareHelper) {
        MEDIA_ERR_LOG("failed to init dataShareHelper");
        return E_DB_FAIL;
    }

    MEDIA_DEBUG_LOG("Query key: %{public}s", key.c_str());
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("KEYWORD", key);
    std::vector<std::string> columns = {"value"};
    int32_t userId = GetUserId();
    std::string queryUri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_" +
                           std::to_string(userId) + "?Proxy=true&key=" + key;
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
    MEDIA_DEBUG_LOG("Query success, value: %{public}s", value.c_str());
    return E_OK;
}

bool SettingsDataManager::GetHdcDeviceId(std::string& deviceId)
{
    #ifdef MEDIA_LIBRARY_MEMOSPACE_SERVICE_SUPPORT
        int hdcRet = Memospace::GetHdcDeviceId(deviceId);
        if (hdcRet != 0) {
            MEDIA_ERR_LOG("fail to get real device Id, ret:%{public}d", hdcRet);
            deviceId = "";
            return false;
        }
        MEDIA_INFO_LOG("get hdc deviceId: %{public}s", deviceId.c_str());
        return true;
    #else
        MEDIA_WARN_LOG("hdc device is not supprted");
        deviceId = "";
        return false;
    #endif
}

static AlbumUploadSwitchStatus StringToAlbumUploadSwitchStatus(const std::string& value)
{
    static const std::unordered_map<std::string, AlbumUploadSwitchStatus> STRING_ALBUM_UPLOAD_MAP = {
        { std::to_string(static_cast<int>(AlbumUploadSwitchStatus::CLOSE)), AlbumUploadSwitchStatus::CLOSE },
        { std::to_string(static_cast<int>(AlbumUploadSwitchStatus::OPEN)), AlbumUploadSwitchStatus::OPEN },
    };
    CHECK_AND_RETURN_RET_LOG(STRING_ALBUM_UPLOAD_MAP.count(value), AlbumUploadSwitchStatus::NONE,
        "invalid AlbumUploadSwitchStatus: %{public}s", value.c_str());
    return STRING_ALBUM_UPLOAD_MAP.at(value);
}

AlbumUploadSwitchStatus SettingsDataManager::GetAllAlbumUploadStatus()
{
    std::string value;
    auto ret = QueryParamInSettingData(ALL_PHOTOS_ALBUM_UPLOAD_USER, value);
    if (ret != E_OK) {
        MEDIA_INFO_LOG("query album upload user key failed, notify photos init");
        int32_t notifyRet = NotifyPhotosSyncSwitchInitByUpdate();
        if (notifyRet == E_OK) {
            ret = QueryParamInSettingData(ALL_PHOTOS_ALBUM_UPLOAD_USER, value);
            if (ret == E_OK) {
                return StringToAlbumUploadSwitchStatus(value);
            }
            MEDIA_WARN_LOG("query album upload user key after init still failed");
        } else {
            MEDIA_WARN_LOG("notify photos init by datashare update failed, ret: %{public}d", notifyRet);
        }
        MEDIA_WARN_LOG("fallback to query album upload device key");
        ret = QueryParamInDeviceSettingData(ALL_PHOTOS_ALBUM_UPLOAD, value);
        if (ret != E_OK) {
            return AlbumUploadSwitchStatus::NONE;
        }
    }
    return StringToAlbumUploadSwitchStatus(value);
}

int32_t SettingsDataManager::UpdateParamInSettingData(const std::string &key, const std::string &value)
{
    MediaSettingDataHelper dataShareHelper;
    if (!dataShareHelper) {
        return E_DB_FAIL;
    }

    MEDIA_INFO_LOG("Update key: %{public}s", key.c_str());
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("KEYWORD", key);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put("VALUE", value); // static_cast<int32_t>(value)

    int32_t userId = GetUserId();
    std::string updateUri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_" +
                            std::to_string(userId) + "?Proxy=true&key=" + key;
    Uri uri(updateUri);
    auto ret = dataShareHelper->UpdateEx(uri, predicates, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(ret.first == DataShare::E_OK, ret.first, "update failed, err: %{public}d", ret.first);
    return ret.first;
}

int32_t SettingsDataManager::InsertParamInSettingData(const std::string &key, const std::string &value)
{
    MediaSettingDataHelper dataShareHelper;
    if (!dataShareHelper) {
        return E_DB_FAIL;
    }

    MEDIA_INFO_LOG("Insert key: %{public}s", key.c_str());
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put("KEYWORD", key);
    valuesBucket.Put("VALUE", value); // static_cast<int32_t>(value)

    int32_t userId = GetUserId();
    std::string insertUri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_" +
                            std::to_string(userId) + "?Proxy=true&key=" + key;
    Uri uri(insertUri);
    std::string result;
    auto ret = dataShareHelper->InsertEx(uri, valuesBucket);
    CHECK_AND_RETURN_RET_LOG(ret.first == DataShare::E_OK, ret.first, "insert failed, return: %{public}d", ret.first);
    return ret.first;
}

int32_t SettingsDataManager::UpdateOrInsertAllPhotosAlbumUpload()
{
    AlbumUploadSwitchStatus ret = GetAllAlbumUploadStatus();
    if (ret != AlbumUploadSwitchStatus::NONE) {
        int32_t updateRet = UpdateParamInSettingData(ALL_PHOTOS_ALBUM_UPLOAD_USER, ALL_PHOTOS_ALBUM_UPLOAD_OFF);
        if (updateRet == E_OK) {
            return updateRet;
        }
        MEDIA_WARN_LOG("update album upload user key failed, fallback to device key, ret: %{public}d", updateRet);
        return UpdateParamInDeviceSettingData(ALL_PHOTOS_ALBUM_UPLOAD, ALL_PHOTOS_ALBUM_UPLOAD_OFF);
    }
    int32_t insertRet = InsertParamInSettingData(ALL_PHOTOS_ALBUM_UPLOAD_USER, ALL_PHOTOS_ALBUM_UPLOAD_OFF);
    if (insertRet == E_OK) {
        return insertRet;
    }
    MEDIA_WARN_LOG("insert album upload user key failed, fallback to device key, ret: %{public}d", insertRet);
    return InsertParamInDeviceSettingData(ALL_PHOTOS_ALBUM_UPLOAD, ALL_PHOTOS_ALBUM_UPLOAD_OFF);
}
}
