/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "NotificationClassificationTest"

#include "notification_classification_test.h"
#include "notification_merging_test.h"
#include "notification_merging.h"
#include "notification_classification.h"
#include "media_log.h"
#include "notify_task_worker.h"
#include "notification_test_data.h"
#include "notify_info_inner.h"

#include <string>
#include <unordered_set>


using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void NotificationClassificationTest::SetUpTestCase(void)
{}

void NotificationClassificationTest::TearDownTestCase(void)
{}

void NotificationClassificationTest::SetUp()
{}

void NotificationClassificationTest::TearDown(void)
{}


HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test001, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test001");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    std::vector<Notification::NotifyInfoInner> notifyInfoInners;
    Media::Notification::NotificationClassification::ConvertNotification(notifyInfoInners, mediaChangeInfos);
    EXPECT_TRUE(mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test001");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test002, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test002");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_ADD,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test002");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test003, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test003");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_ADD_HIDDEN,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test003");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test004, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test004");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_ADD_TRASH,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test004");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test005, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test005");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_REMOVE,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test005");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test006, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test006");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_REMOVE_HIDDEN,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test006");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test007, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test007");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_REMOVE_TRASH,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test007");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test008, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test008");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_NORMAL,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test008");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test009, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test009");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_REMOVE_NORMAL,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test009");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test010, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test010");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_ADD_NORMAL,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test010");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test011, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test011");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_HIDDEN,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test011");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test012, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test012");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_ADD_HIDDEN,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test012");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test013, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test013");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_REMOVE_HIDDEN,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test013");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test014, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test014");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_TRASH,
        {Notification::Priority::NORMAL, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test014");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test015, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test015");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_ADD_TRASH,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test015");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test016, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test016");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UPDATE_REMOVE_TRASH,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test016");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test017, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test017");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_TRASH,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test017");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test018, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test018");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UNTRASH,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test018");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test019, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test019");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_HIDDEN,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test019");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test020, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test020");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_UNHIDDEN,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test020");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test021, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test021");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& deletePhotoData1 = OHOS::Media::Notification::deletePhotoData1;
    const auto& deletePhotoData2 = OHOS::Media::Notification::deletePhotoData2;
    auto notifyInfos = Notification::NotificationTestData::buildPhotoNotifyTaskInfo(
        Notification::NotifyTableType::PHOTOS,
        {deletePhotoData1, deletePhotoData2},
        Notification::AssetRefreshOperation::ASSET_OPERATION_RECHECK,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test021");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test022, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test022");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto& albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    auto notifyInfos = Notification::NotificationTestData::buildAlbumNotifyTaskInfo(
        Notification::NotifyTableType::PHOTO_ALBUM,
        {albumChangeData1, albumChangeData2},
        Notification::AlbumRefreshOperation::ALBUM_OPERATION_ADD,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test022");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test023, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test023");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto& albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    auto notifyInfos = Notification::NotificationTestData::buildAlbumNotifyTaskInfo(
        Notification::NotifyTableType::PHOTO_ALBUM,
        {albumChangeData1, albumChangeData2},
        Notification::AlbumRefreshOperation::ALBUM_OPERATION_UPDATE,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test023");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test024, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test024");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto& albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    auto notifyInfos = Notification::NotificationTestData::buildAlbumNotifyTaskInfo(
        Notification::NotifyTableType::PHOTO_ALBUM,
        {albumChangeData1, albumChangeData2},
        Notification::AlbumRefreshOperation::ALBUM_OPERATION_REMOVE,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test024");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test025, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test025");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto& albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    auto notifyInfos = Notification::NotificationTestData::buildAlbumNotifyTaskInfo(
        Notification::NotifyTableType::PHOTO_ALBUM,
        {albumChangeData1, albumChangeData2},
        Notification::AlbumRefreshOperation::ALBUM_OPERATION_UPDATE_HIDDEN,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test025");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test026, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test026");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto& albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    auto notifyInfos = Notification::NotificationTestData::buildAlbumNotifyTaskInfo(
        Notification::NotifyTableType::PHOTO_ALBUM,
        {albumChangeData1, albumChangeData2},
        Notification::AlbumRefreshOperation::ALBUM_OPERATION_UPDATE_TRASH,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test026");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test027, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test027");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto& albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    auto notifyInfos = Notification::NotificationTestData::buildAlbumNotifyTaskInfo(
        Notification::NotifyTableType::PHOTO_ALBUM,
        {albumChangeData1, albumChangeData2},
        Notification::AlbumRefreshOperation::ALBUM_OPERATION_RECHECK,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());
    MEDIA_INFO_LOG("end medialib_notification_classification_test027");
}

HWTEST_F(NotificationClassificationTest, medialib_notification_classification_test028, TestSize.Level1)
{
    MEDIA_INFO_LOG("enter medialib_notification_classification_test028");
    Notification::NotificationClassification::AddAlbum("albumId");
    std::vector<Notification::MediaChangeInfo> mediaChangeInfos;
    const auto& albumChangeData1 = OHOS::Media::Notification::albumChangeData1;
    const auto& albumChangeData2 = OHOS::Media::Notification::albumChangeData2;
    auto notifyInfos = Notification::NotificationTestData::buildAlbumNotifyTaskInfo(
        Notification::NotifyTableType::PHOTO_ALBUM,
        {albumChangeData1, albumChangeData2},
        Notification::AlbumRefreshOperation::ALBUM_OPERATION_UPDATE,
        {Notification::Priority::EMERGENCY, 1}
    );
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_TRUE(!mediaChangeInfos.empty());

    int32_t albumId = albumChangeData1.infoBeforeChange_.albumId_;
    Notification::NotificationClassification::AddAlbum(to_string(albumId));
    size_t mediaChangeInfosSize = 2;
    mediaChangeInfos.clear();
    Notification::NotificationClassification::ConvertNotification(notifyInfos, mediaChangeInfos);
    EXPECT_EQ(mediaChangeInfos.size(), mediaChangeInfosSize);
    MEDIA_INFO_LOG("end medialib_notification_classification_test028");
}

} // namespace Media
} // namespace OHOS