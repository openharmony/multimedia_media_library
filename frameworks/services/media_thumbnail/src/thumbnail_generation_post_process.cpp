/*
* Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Thumbnail"

#include "thumbnail_generation_post_process.h"

#include "asset_accurate_refresh.h"
#include "dfx_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_tracer.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "thumbnail_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

int32_t ThumbnailGenerationPostProcess::PostProcess(ThumbnailData& data, const ThumbRdbOpt& opts)
{
    CHECK_AND_RETURN_RET_INFO_LOG(!data.rdbUpdateCache.IsEmpty(), E_OK, "RdbUpdateCache is empty, no need update.");
    int32_t err = E_OK;
    bool hasGeneratedThumb = HasGeneratedThumb(data);
    MEDIA_INFO_LOG("HasGeneratedThumb: %{public}d", hasGeneratedThumb);
    if (!hasGeneratedThumb) {
        err = UpdateCachedRdbValue(data, opts);
        CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "UpdateCachedRdbValue failed. err: %{public}d", err);
        data.rdbUpdateCache.Clear();
        return E_OK;
    }

    // 必须在更新数据库前获取通知类型
    NotifyType notifyType;
    err = GetNotifyType(data, opts, notifyType);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "GetNotifyType failed. err: %{public}d", err);

    AccurateRefresh::AssetAccurateRefresh assetRefresh;
    int32_t changedRows;
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::MEDIA_ID, data.id);
    auto ret = assetRefresh.Update(changedRows, data.rdbUpdateCache, predicates);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "AssetRefresh.Update failed. err: %{public}d", ret);
    data.rdbUpdateCache.Clear();
    ret = assetRefresh.Notify();
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Notify failed. err: %{public}d", ret);

    err = Notify(data, notifyType);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "Notify failed. err: %{public}d", err);
    return E_OK;
}

int32_t ThumbnailGenerationPostProcess::UpdateCachedRdbValue(ThumbnailData& data, const ThumbRdbOpt& opts)
{
    const string& photosTable = PhotoColumn::PHOTOS_TABLE;
    CHECK_AND_RETURN_RET_LOG(opts.store != nullptr, E_ERR, "RdbStore is nullptr");
    CHECK_AND_RETURN_RET_LOG(opts.table == photosTable, false,
        "Not %{public}s table, table: %{public}s", photosTable.c_str(), opts.table.c_str());
    MediaLibraryTracer tracer;
    tracer.Start("UpdateCachedRdbValue opts.store->Update");
    int32_t changedRows;
    int32_t err = opts.store->Update(changedRows, photosTable,
        data.rdbUpdateCache, MEDIA_DATA_DB_ID + " = ?", { data.id });
    CHECK_AND_RETURN_RET_LOG(err == E_OK, err, "UpdateCachedRdbValue failed. table: %{public}s, err: %{public}d",
        photosTable.c_str(), err);
    CHECK_AND_RETURN_RET_LOG(changedRows != 0, E_ERR, "Rdb has no data, id:%{public}s, DeleteThumbnail:%{public}d",
        data.id.c_str(), ThumbnailUtils::DeleteThumbnailDirAndAstc(opts, data));
    return E_OK;
}

int32_t ThumbnailGenerationPostProcess::Notify(const ThumbnailData& data, const NotifyType notifyType)
{
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_RET_LOG(watch != nullptr, E_ERR, "SendThumbNotify watch is nullptr");
    watch->Notify(data.fileUri, notifyType);
    MEDIA_INFO_LOG("ThumbnailGenerationPostProcess::Notify() "
        "fileUri: %{public}s, notifyType: %{public}d", data.fileUri.c_str(), notifyType);
    return E_OK;
}


int32_t ThumbnailGenerationPostProcess::GetNotifyType(const ThumbnailData& data,
    const ThumbRdbOpt& opts, NotifyType& notifyType)
{
    int32_t err = E_OK;
    CHECK_AND_RETURN_RET_LOG(opts.store != nullptr, E_ERR, "RdbStore is nullptr");
    CHECK_AND_RETURN_RET_LOG(!data.id.empty(), E_ERR, "Data.id is empty");

    vector<string> columns = { PhotoColumn::PHOTO_THUMBNAIL_VISIBLE };
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + data.id;
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.SetWhereClause(strQueryCondition);

    auto resultSet = opts.store->QueryByStep(rdbPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_ERR, "QueryByStep() result is null");
    auto ret = resultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_ERR, "ResultSet->GoToFirstRow() failed");
    int32_t thumbnailVisible = GetInt32Val(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, resultSet);

    notifyType = thumbnailVisible > 0 ? NotifyType::NOTIFY_THUMB_UPDATE : NotifyType::NOTIFY_THUMB_ADD;
    return E_OK;
}

bool ThumbnailGenerationPostProcess::HasGeneratedThumb(const ThumbnailData& data)
{
    ValueObject valueObject;
    bool hasThumbReadyColumn = data.rdbUpdateCache.GetObject(PhotoColumn::PHOTO_THUMBNAIL_READY, valueObject);
    CHECK_AND_RETURN_RET_INFO_LOG(hasThumbReadyColumn, false, "Do not cache thumbnail_ready value in photos table");

    int64_t thumbReady;
    valueObject.GetLong(thumbReady);
    return thumbReady != static_cast<int64_t>(ThumbnailReady::GENERATE_THUMB_RETRY);
}

} // namespace Media
} // namespace OHOS