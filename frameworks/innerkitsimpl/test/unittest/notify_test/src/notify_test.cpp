/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#define MLOG_TAG "NotifyTest"

#include "notify_test.h"

#include "ability_context_impl.h"
#include "fetch_result.h"
#include "get_self_permissions.h"
#include "iservice_registry.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#define private public
#include "medialibrary_notify.h"
#undef private
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "system_ability_definition.h"


namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using OHOS::DataShare::DataShareValuesBucket;
using OHOS::DataShare::DataSharePredicates;

enum DefaultAlbumId: int32_t {
    FAVORITE_ALBUM = 1,
    VIDEO_ALBUM,
    HIDDEN_ALBUM,
    TRASH_ALBUM,
    SCREENSHOTS_ALBUM,
    CAMERA_ALBUM,
};
static constexpr int STORAGE_MANAGER_ID = 5003;
static constexpr int OBS_TMP_ID = 1;
static constexpr int OBS_TMP_ALBUM_ID = 10;
static constexpr int LIST_SIZE = 1;
static constexpr int64_t DATE_ADD = 6666666;
static constexpr int64_t DATE_MODIFY = 6666667;
shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;

void CheckGetAlbumIdBySubType(PhotoAlbumSubType photoAlbumSubType, DefaultAlbumId defaultAlbumId)
{
    auto context = make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    MediaLibraryUnistoreManager::GetInstance().Init(context);
    auto watch = MediaLibraryNotify::GetInstance();
    int albumId = watch->GetAlbumIdBySubType(photoAlbumSubType);
    EXPECT_EQ(defaultAlbumId, albumId);
    MediaLibraryUnistoreManager::GetInstance().Stop();
}

void CheckFileNotify(NotifyType notifyType)
{
    string uriStr = PhotoColumn::PHOTO_URI_PREFIX + to_string(OBS_TMP_ID);
    Uri uri(uriStr);
    shared_ptr<TestObserver> obs = make_shared<TestObserver>();
    if (sDataShareHelper_ == nullptr) {
        return;
    }
    sDataShareHelper_->RegisterObserverExt(uri, obs, true);
    MediaLibraryNotify::GetInstance()->Notify(uriStr, notifyType);
    {
        unique_lock<mutex> lock(obs->mutex_);
        if (obs->condition_.wait_for(lock, 2s) == cv_status::no_timeout) {
            EXPECT_EQ(obs->changeInfo_.changeType_, static_cast<DataShareObserver::ChangeType>(notifyType));
            EXPECT_EQ(obs->changeInfo_.uris_.size(), 1);
            EXPECT_EQ(obs->changeInfo_.uris_.begin()->ToString(), uriStr);
        } else {
            EXPECT_TRUE(false);
        }
    }
}

void SolveAlbumNotify(shared_ptr<TestObserver> obs, string assetStr)
{
    uint8_t *data = new (nothrow) uint8_t[obs->changeInfo_.size_];
    if (data == nullptr) {
        return;
    }
    int copyRet = memcpy_s(data, obs->changeInfo_.size_, obs->changeInfo_.data_, obs->changeInfo_.size_);
    if (copyRet != 0) {
        return;
    }
    shared_ptr<MessageParcel> parcel = make_shared<MessageParcel>();
    if (parcel->ParseFrom(reinterpret_cast<uintptr_t>(data), obs->changeInfo_.size_)) {
        uint32_t len = 0;
        if (!parcel->ReadUint32(len)) {
            return;
        }
        EXPECT_EQ(len, LIST_SIZE);
        for (uint32_t i = 0; i < len; i++) {
            string subUri = parcel->ReadString();
            if (subUri.empty()) {
                return;
            }
            EXPECT_EQ(subUri, assetStr);
        }
    }
}

void CheckAlbumNotify(NotifyType notifyType, DataShareObserver::ChangeType changeType)
{
    string assetStr = PhotoColumn::PHOTO_URI_PREFIX + to_string(OBS_TMP_ID);
    string albumStr = PhotoAlbumColumns::ALBUM_URI_PREFIX  + to_string(OBS_TMP_ALBUM_ID);
    Uri uri(albumStr);
    shared_ptr<TestObserver> obs = make_shared<TestObserver>();
    if (sDataShareHelper_ == nullptr) {
        return;
    }
    sDataShareHelper_->RegisterObserverExt(uri, obs, true);
    MediaLibraryNotify::GetInstance()->Notify(assetStr, notifyType, OBS_TMP_ALBUM_ID);
    {
        unique_lock<mutex> lock(obs->mutex_);
        if (obs->condition_.wait_for(lock, 2s) == cv_status::no_timeout) {
            if (obs->changeInfo_.size_ > 0) {
                SolveAlbumNotify(obs, assetStr);
            } else {
                EXPECT_TRUE(false);
            }
            EXPECT_EQ(obs->changeInfo_.changeType_, changeType);
            EXPECT_EQ(obs->changeInfo_.uris_.size(), LIST_SIZE);
            EXPECT_EQ(obs->changeInfo_.uris_.begin()->ToString(), albumStr);
        } else {
            EXPECT_TRUE(false);
        }
    }
}

void CheckCloseAssetNotify(bool isCreate)
{
    string uriStr = PhotoColumn::PHOTO_URI_PREFIX + to_string(OBS_TMP_ID);
    Uri uri(uriStr);
    shared_ptr<TestObserver> obs = make_shared<TestObserver>();
    if (sDataShareHelper_ == nullptr) {
        return;
    }
    sDataShareHelper_->RegisterObserverExt(uri, obs, true);
    shared_ptr<FileAsset> closeAsset = make_shared<FileAsset>();
    closeAsset->SetId(OBS_TMP_ID);
    closeAsset->SetMediaType(MediaType::MEDIA_TYPE_IMAGE);
    if (isCreate) {
        closeAsset->SetDateAdded(DATE_ADD);
        closeAsset->SetDateModified(0);
    } else {
        closeAsset->SetDateAdded(DATE_ADD);
        closeAsset->SetDateModified(DATE_MODIFY);
    }
    MediaLibraryNotify::GetInstance()->Notify(closeAsset);
    {
        unique_lock<mutex> lock(obs->mutex_);
        if (obs->condition_.wait_for(lock, 2s) == cv_status::no_timeout) {
            if (isCreate) {
                EXPECT_EQ(obs->changeInfo_.changeType_,
                    static_cast<DataShareObserver::ChangeType>(NotifyType::NOTIFY_ADD));
            } else {
                EXPECT_EQ(obs->changeInfo_.changeType_,
                    static_cast<DataShareObserver::ChangeType>(NotifyType::NOTIFY_UPDATE));
            }
            EXPECT_EQ(obs->changeInfo_.uris_.size(), 1);
            EXPECT_EQ(obs->changeInfo_.uris_.begin()->ToString(), uriStr);
        } else {
            EXPECT_TRUE(false);
        }
    }
}

void NotifyTest::SetUpTestCase()
{
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("NotifyTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saManager != nullptr);

    auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_ID);
    ASSERT_TRUE(remoteObj != nullptr);

    sDataShareHelper_ = DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
    ASSERT_TRUE(sDataShareHelper_ != nullptr);
}

void NotifyTest::TearDownTestCase() {}

// SetUp:Execute before each test case
void NotifyTest::SetUp() {}

void NotifyTest::TearDown() {}

/**
 * @tc.name: get_album_id_by_subtype_001
 * @tc.desc: Get default album id
 *           1. Create an album called "get_album_id_by_subtype_001"
 *           2. VIDEO_ALBUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, get_album_id_by_subtype_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("get_album_id_by_subtype_001 enter");
    CheckGetAlbumIdBySubType(PhotoAlbumSubType::VIDEO, DefaultAlbumId::VIDEO_ALBUM);
    MEDIA_INFO_LOG("get_album_id_by_subtype_001 exit");
}

/**
 * @tc.name: get_album_id_by_subtype_002
 * @tc.desc: Get default album id
 *           1. Create an album called "get_album_id_by_subtype_002"
 *           2. FAVORITE_ALBUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, get_album_id_by_subtype_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("get_album_id_by_subtype_002 enter");
    CheckGetAlbumIdBySubType(PhotoAlbumSubType::FAVORITE, DefaultAlbumId::FAVORITE_ALBUM);
    MEDIA_INFO_LOG("get_album_id_by_subtype_002 exit");
}

/**
 * @tc.name: get_album_id_by_subtype_003
 * @tc.desc: Get default album id
 *           1. Create an album called "get_album_id_by_subtype_003"
 *           2. HIDDEN_ALBUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, get_album_id_by_subtype_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("get_album_id_by_subtype_003 enter");
    CheckGetAlbumIdBySubType(PhotoAlbumSubType::HIDDEN, DefaultAlbumId::HIDDEN_ALBUM);
    MEDIA_INFO_LOG("get_album_id_by_subtype_003 exit");
}

/**
 * @tc.name: get_album_id_by_subtype_004
 * @tc.desc: Get default album id
 *           1. Create an album called "get_album_id_by_subtype_004"
 *           2. TRASH_ALBUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, get_album_id_by_subtype_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("get_album_id_by_subtype_004 enter");
    CheckGetAlbumIdBySubType(PhotoAlbumSubType::TRASH, DefaultAlbumId::TRASH_ALBUM);
    MEDIA_INFO_LOG("get_album_id_by_subtype_004 exit");
}

/**
 * @tc.name: get_album_id_by_subtype_005
 * @tc.desc: Get default album id
 *           1. Create an album called "get_album_id_by_subtype_005"
 *           2. SCREENSHOTS_ALBUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, get_album_id_by_subtype_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("get_album_id_by_subtype_005 enter");
    CheckGetAlbumIdBySubType(PhotoAlbumSubType::SCREENSHOT, DefaultAlbumId::SCREENSHOTS_ALBUM);
    MEDIA_INFO_LOG("get_album_id_by_subtype_005 exit");
}

/**
 * @tc.name: get_album_id_by_subtype_006
 * @tc.desc: Get default album id
 *           1. Create an album called "get_album_id_by_subtype_006"
 *           2. CAMERA_ALBUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, get_album_id_by_subtype_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("get_album_id_by_subtype_006 enter");
    CheckGetAlbumIdBySubType(PhotoAlbumSubType::CAMERA, DefaultAlbumId::CAMERA_ALBUM);
    MEDIA_INFO_LOG("get_album_id_by_subtype_006 exit");
}

/**
 * @tc.name: asset_on_change_001
 * @tc.desc: solve asset and get message
 *           1. RegisterObserverExt called "asset_on_change_001"
 *           2. NotifyType::NOTIFY_ADD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, asset_on_change_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("asset_on_change_001 enter");
    CheckFileNotify(NotifyType::NOTIFY_ADD);
    MEDIA_INFO_LOG("asset_on_change_001 exit");
}

/**
 * @tc.name: asset_on_change_002
 * @tc.desc: solve asset and get message
 *           1. RegisterObserverExt called "asset_on_change_002"
 *           2. NotifyType::NOTIFY_UPDATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, asset_on_change_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("asset_on_change_002 enter");
    CheckFileNotify(NotifyType::NOTIFY_UPDATE);
    MEDIA_INFO_LOG("asset_on_change_002 exit");
}

/**
 * @tc.name: asset_on_change_003
 * @tc.desc: solve asset and get message
 *           1. RegisterObserverExt called "asset_on_change_003"
 *           2. NotifyType::NOTIFY_REMOVE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, asset_on_change_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("asset_on_change_003 enter");
    CheckFileNotify(NotifyType::NOTIFY_REMOVE);
    MEDIA_INFO_LOG("asset_on_change_003 exit");
}

/**
 * @tc.name: album_on_change_001
 * @tc.desc: solve album and get message
 *           1. RegisterObserverExt called "album_on_change_001"
 *           2. NotifyType::NOTIFY_ALBUM_ADD_ASSET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, album_on_change_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("album_on_change_001 enter");
    CheckAlbumNotify(NotifyType::NOTIFY_ALBUM_ADD_ASSET, DataShareObserver::ChangeType::INSERT);
    MEDIA_INFO_LOG("album_on_change_001 exit");
}

/**
 * @tc.name: album_on_change_002
 * @tc.desc: solve album and get message
 *           1. RegisterObserverExt called "album_on_change_002"
 *           2. NotifyType::NOTIFY_ALBUM_REMOVE_ASSET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, album_on_change_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("album_on_change_002 enter");
    CheckAlbumNotify(NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, DataShareObserver::ChangeType::DELETE);
    MEDIA_INFO_LOG("album_on_change_002 exit");
}

/**
 * @tc.name: close_asset_on_change_001
 * @tc.desc: solve close asset and get message
 *           1. RegisterObserverExt called "close_asset_on_change_001"
 *           2. isCreate == true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, close_asset_on_change_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("close_asset_on_change_001 enter");
    CheckCloseAssetNotify(true);
    MEDIA_INFO_LOG("close_asset_on_change_001 exit");
}

/**
 * @tc.name: close_asset_on_change_002
 * @tc.desc: solve close asset and get message
 *           1. RegisterObserverExt called "close_asset_on_change_002"
 *           2. isCreate == false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NotifyTest, close_asset_on_change_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("close_asset_on_change_002 enter");
    CheckCloseAssetNotify(false);
    MEDIA_INFO_LOG("close_asset_on_change_002 exit");
}
} // namespace OHOS::Media
