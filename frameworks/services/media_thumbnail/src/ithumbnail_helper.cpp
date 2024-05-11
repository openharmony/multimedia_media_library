/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "ithumbnail_helper.h"

#include "ability_manager_client.h"
#include "background_task_mgr_helper.h"
#include "dfx_utils.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "media_column.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_notify.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "rdb_predicates.h"
#include "rdb_helper.h"
#include "single_kvstore.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_worker_manager.h"
#include "post_event_utils.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
void IThumbnailHelper::CreateThumbnails(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateThumbnails failed, data is null");
        return;
    }
    DoCreateThumbnails(data->opts_, data->thumbnailData_);
    ThumbnailUtils::RecordCostTimeAndReport(data->thumbnailData_.stats);
    if (data->opts_.path.find(ROOT_MEDIA_DIR + PHOTO_BUCKET) != string::npos) {
        MediaLibraryPhotoOperations::StoreThumbnailSize(data->opts_.row, data->opts_.path);
    }
}

void IThumbnailHelper::CreateLcd(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateLcd failed, data is null");
        return;
    }
    DoCreateLcd(data->opts_, data->thumbnailData_);
}

void IThumbnailHelper::CreateThumbnail(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateThumbnail failed, data is null");
        return;
    }
    DoCreateThumbnail(data->opts_, data->thumbnailData_);
    ThumbnailUtils::RecordCostTimeAndReport(data->thumbnailData_.stats);
    if (data->opts_.path.find(ROOT_MEDIA_DIR + PHOTO_BUCKET) != string::npos) {
        MediaLibraryPhotoOperations::StoreThumbnailSize(data->opts_.row, data->opts_.path);
    }
}

void IThumbnailHelper::CreateAstc(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateAstc failed, data is null");
        return;
    }
    DoCreateAstc(data->opts_, data->thumbnailData_);
    ThumbnailUtils::RecordCostTimeAndReport(data->thumbnailData_.stats);
}

void IThumbnailHelper::AddThumbnailGenerateTask(ThumbnailGenerateExecute executor, ThumbRdbOpt &opts,
    ThumbnailData &thumbData, const ThumbnailTaskType &taskType, const ThumbnailTaskPriority &priority)
{
    std::shared_ptr<ThumbnailGenerateWorker> thumbnailWorker =
        ThumbnailGenerateWorkerManager::GetInstance().GetThumbnailWorker(taskType);
    if (thumbnailWorker == nullptr) {
        MEDIA_ERR_LOG("thumbnailWorker is null");
        return;
    }

    std::shared_ptr<ThumbnailTaskData> taskData = std::make_shared<ThumbnailTaskData>(opts, thumbData);
    std::shared_ptr<ThumbnailGenerateTask> task = std::make_shared<ThumbnailGenerateTask>(executor, taskData);
    thumbnailWorker->AddTask(task, priority);
}

ThumbnailWait::ThumbnailWait(bool release) : needRelease_(release)
{}

ThumbnailWait::~ThumbnailWait()
{
    if (needRelease_) {
        Notify();
    }
}

ThumbnailMap ThumbnailWait::thumbnailMap_;
std::shared_mutex ThumbnailWait::mutex_;

static bool WaitFor(const shared_ptr<ThumbnailSyncStatus> &thumbnailWait, int waitMs, unique_lock<mutex> &lck)
{
    bool ret = thumbnailWait->cond_.wait_for(lck, chrono::milliseconds(waitMs),
        [thumbnailWait]() { return thumbnailWait->isSyncComplete_; });
    if (!ret) {
        MEDIA_INFO_LOG("IThumbnailHelper::Wait wait for lock timeout");
    }
    return ret;
}

WaitStatus ThumbnailWait::InsertAndWait(const string &id, bool isLcd)
{
    id_ = id;

    if (isLcd) {
        id_ += THUMBNAIL_LCD_SUFFIX;
    } else {
        id_ += THUMBNAIL_THUMB_SUFFIX;
    }
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        writeLck.unlock();
        MEDIA_INFO_LOG("Waiting for thumbnail generation, id: %{public}s", id_.c_str());
        thumbnailWait->cond_.wait(lck, [weakPtr = weak_ptr(thumbnailWait)]() {
            if (auto sharedPtr = weakPtr.lock()) {
                return sharedPtr->isSyncComplete_;
            } else {
                return true;
            }
        });
        if (thumbnailWait->isCreateThumbnailSuccess_) {
            MEDIA_INFO_LOG("Thumbnail generated successfully");
            return WaitStatus::WAIT_SUCCESS;
        } else {
            MEDIA_ERR_LOG("Failed to generate thumbnail");
            return WaitStatus::WAIT_FAILED;
        }
    } else {
        shared_ptr<ThumbnailSyncStatus> thumbnailWait = make_shared<ThumbnailSyncStatus>();
        thumbnailMap_.insert(ThumbnailMap::value_type(id_, thumbnailWait));
        return WaitStatus::INSERT;
    }
}

void ThumbnailWait::CheckAndWait(const string &id, bool isLcd)
{
    id_ = id;

    if (isLcd) {
        id_ += THUMBNAIL_LCD_SUFFIX;
    } else {
        id_ += THUMBNAIL_THUMB_SUFFIX;
    }
    shared_lock<shared_mutex> readLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        readLck.unlock();
        WaitFor(thumbnailWait, WAIT_FOR_MS, lck);
    }
}

void ThumbnailWait::UpdateThumbnailMap()
{
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        {
            unique_lock<mutex> lck(thumbnailWait->mtx_);
            writeLck.unlock();
            thumbnailWait->isCreateThumbnailSuccess_ = true;
        }
    } else {
        MEDIA_ERR_LOG("Update ThumbnailMap failed, id: %{public}s", id_.c_str());
    }
}

void ThumbnailWait::Notify()
{
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        thumbnailMap_.erase(iter);
        {
            unique_lock<mutex> lck(thumbnailWait->mtx_);
            writeLck.unlock();
            thumbnailWait->isSyncComplete_ = true;
        }
        thumbnailWait->cond_.notify_all();
    }
}

bool IThumbnailHelper::TryLoadSource(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (data.source != nullptr) {
        return true;
    }
    
    if (!ThumbnailUtils::LoadSourceImage(data)) {
        if (opts.path.empty()) {
            MEDIA_ERR_LOG("LoadSourceImage faild, %{private}s", data.path.c_str());
            VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
                {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
            PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
            return false;
        } else {
            opts.path = "";
            ThumbnailUtils::GetThumbnailInfo(opts, data);
            if (access(data.path.c_str(), F_OK) == 0) {
                return true;
            }
            if (!ThumbnailUtils::LoadSourceImage(data)) {
                VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
                    {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN}, {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
                PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
                return false;
            }
        }
    }
    return true;
}

bool IThumbnailHelper::DoCreateLcd(ThumbRdbOpt &opts, ThumbnailData &data)
{
    ThumbnailWait thumbnailWait(true);
    auto ret = thumbnailWait.InsertAndWait(data.id, true);
    if (ret != WaitStatus::INSERT) {
        return ret == WaitStatus::WAIT_SUCCESS;
    }

    if (IsCreateLcdSuccess(opts, data)) {
        thumbnailWait.UpdateThumbnailMap();
        return true;
    }
    return false;
}

bool IThumbnailHelper::IsCreateLcdSuccess(ThumbRdbOpt &opts, ThumbnailData &data)
{
    data.useThumbAsSource = false;
    data.isLoadingFromThumbToLcd = false;
    if (!TryLoadSource(opts, data)) {
        MEDIA_ERR_LOG("load source is nullptr path: %{public}s", opts.path.c_str());
        return false;
    }

    if (data.source == nullptr) {
        MEDIA_ERR_LOG("source is nullptr");
        return false;
    }

    shared_ptr<string> pathPtr = make_shared<string>(data.path);
    shared_ptr<PixelMap> lcdSource = data.source;
    if (data.lcdDesiredSize.width != data.source->GetWidth()) {
        MEDIA_INFO_LOG("Copy and resize data source for lcd desiredSize: %{public}s",
            DfxUtils::GetSafePath(opts.path).c_str());
        Media::InitializationOptions opts;
        auto copySource = PixelMap::Create(*data.source, opts);
        lcdSource = std::move(copySource);
        float widthScale = (1.0f * data.lcdDesiredSize.width) / data.source->GetWidth();
        float heightScale = (1.0f * data.lcdDesiredSize.height) / data.source->GetHeight();
        lcdSource->scale(widthScale, heightScale);
    }
    if (!ThumbnailUtils::CompressImage(lcdSource, data.lcd, data.mediaType == MEDIA_TYPE_AUDIO, pathPtr)) {
        MEDIA_ERR_LOG("CompressImage faild");
        return false;
    }

    int err = ThumbnailUtils::TrySaveFile(data, ThumbnailType::LCD);
    if (err < 0) {
        MEDIA_ERR_LOG("SaveLcd faild %{public}d", err);
        return false;
    }

    data.lcd.clear();
    if (opts.table == PhotoColumn::PHOTOS_TABLE) {
        if (!ThumbnailUtils::UpdateLcdInfo(opts, data, err)) {
            MEDIA_INFO_LOG("UpdateLcdInfo faild err : %{public}d", err);
            return false;
        }
    }

    return true;
}

bool IThumbnailHelper::GenThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, const ThumbnailType type)
{
    if (data.source == nullptr) {
        MEDIA_ERR_LOG("source is nullptr when generate type: %{public}s", TYPE_NAME_MAP.at(type).c_str());
        return false;
    }

    if (type == ThumbnailType::THUMB || type == ThumbnailType::THUMB_ASTC) {
        if (data.source == nullptr) {
            MEDIA_ERR_LOG("source is nullptr");
            return false;
        }

        if (!ThumbnailUtils::CompressImage(data.source, type == ThumbnailType::THUMB ? data.thumbnail : data.thumbAstc,
            false, nullptr, type == ThumbnailType::THUMB_ASTC)) {
            MEDIA_ERR_LOG("CompressImage faild id %{private}s", opts.row.c_str());
            VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
                {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
            PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
            return false;
        }
    } else if (type == ThumbnailType::MTH_ASTC || type == ThumbnailType::YEAR_ASTC) {
        if (!ThumbnailUtils::CheckDateAdded(opts, data)) {
            MEDIA_ERR_LOG("CheckDateAdded failed in GenThumbnail");
            return false;
        }
        if (!GenMonthAndYearAstcData(data, type)) {
            MEDIA_ERR_LOG("GenMonthAndYearAstcData failed in GenThumbnail");
            return false;
        }
    } else {
        MEDIA_ERR_LOG("invalid thumbnail type: %{public}d", type);
        return false;
    }

    int err = ThumbnailUtils::TrySaveFile(data, type);
    if (err < 0) {
        MEDIA_ERR_LOG("SaveThumbnailData faild %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    data.thumbnail.clear();
    return true;
}

bool IThumbnailHelper::GenMonthAndYearAstcData(ThumbnailData &data, const ThumbnailType type)
{
    Size size;
    if (type == ThumbnailType::MTH_ASTC) {
        size = {DEFAULT_MTH_SIZE, DEFAULT_MTH_SIZE };
    } else if (type == ThumbnailType::YEAR_ASTC) {
        size = {DEFAULT_YEAR_SIZE, DEFAULT_YEAR_SIZE };
    } else {
        MEDIA_ERR_LOG("invalid thumbnail type");
        return false;
    }

    ThumbnailUtils::GenTargetPixelmap(data, size);
    if (!ThumbnailUtils::CompressImage(data.source,
        (type == ThumbnailType::MTH_ASTC) ? data.monthAstc : data.yearAstc, false, nullptr, true)) {
        MEDIA_ERR_LOG("CompressImage to astc failed");
        return false;
    }
    return true;
}

bool IThumbnailHelper::UpdateThumbnailState(const ThumbRdbOpt &opts, const ThumbnailData &data)
{
    int32_t err = UpdateAstcState(opts, data);
    if (err != E_OK) {
        MEDIA_ERR_LOG("update has_astc failed, err = %{public}d", err);
        return false;
    }

    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("watch is nullptr");
        return false;
    }
    watch->Notify(data.fileUri, NotifyType::NOTIFY_THUMB_ADD);
    return true;
}

int32_t IThumbnailHelper::UpdateAstcState(const ThumbRdbOpt &opts, const ThumbnailData &data)
{
    int32_t err = 0;
    ValuesBucket values;
    int changedRows;
    int64_t thumbnail_status = 0;
    if (data.needUpload) {
        thumbnail_status = static_cast<int64_t>(ThumbnailReady::THUMB_TO_UPLOAD);
    } else {
        thumbnail_status = static_cast<int64_t>(ThumbnailReady::GENERATE_THUMB_COMPLETED);
    }
    values.PutLong(PhotoColumn::PHOTO_HAS_ASTC, thumbnail_status);
    err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { data.id });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return E_ERR;
    }
    return E_OK;
}

bool IThumbnailHelper::DoCreateThumbnail(ThumbRdbOpt &opts, ThumbnailData &data)
{
    ThumbnailWait thumbnailWait(true);
    auto ret = thumbnailWait.InsertAndWait(data.id, false);
    if (ret != WaitStatus::INSERT) {
        return ret == WaitStatus::WAIT_SUCCESS;
    }

    if (IsCreateThumbnailSuccess(opts, data)) {
        thumbnailWait.UpdateThumbnailMap();
        return true;
    }
    return false;
}

bool IThumbnailHelper::IsCreateThumbnailSuccess(ThumbRdbOpt &opts, ThumbnailData &data)
{
    data.useThumbAsSource = true;
    data.isLoadingFromThumbToLcd = false;
    if (!TryLoadSource(opts, data)) {
        MEDIA_ERR_LOG("DoCreateThumbnail failed, try to load source failed, id: %{public}s", data.id.c_str());
        return false;
    }

    if (!GenThumbnail(opts, data, ThumbnailType::THUMB)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
            {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    if (opts.table == AudioColumn::AUDIOS_TABLE) {
        MEDIA_DEBUG_LOG("AUDIOS_TABLE, no need to create all thumbnail");
        return true;
    }

    if (ThumbnailUtils::IsSupportGenAstc() && !GenThumbnail(opts, data, ThumbnailType::THUMB_ASTC)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN}, {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    // for some device that do not support KvStore, no need to generate the month and year astc.
    if (MediaLibraryKvStoreManager::GetInstance()
        .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC) == nullptr) {
        MEDIA_DEBUG_LOG("kvStore is nullptr, no need to create month and year astc");
        return true;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::MTH_ASTC)) {
        return false;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::YEAR_ASTC)) {
        return false;
    }

    // After all thumbnails are generated, the value of column "has_astc" in rdb
    // needs to be updated, and application should receive a notification at the same time.
    if (!UpdateThumbnailState(opts, data)) {
        MEDIA_ERR_LOG("UpdateThumbnailState fail");
        return false;
    }
    return true;
}

bool IThumbnailHelper::DoCreateThumbnails(ThumbRdbOpt &opts, ThumbnailData &data)
{
    MEDIA_INFO_LOG("Start DoCreateThumbnails, id: %{public}s, path: %{public}s", data.id.c_str(), data.path.c_str());
    if (!DoCreateLcd(opts, data)) {
        MEDIA_ERR_LOG("Fail to create lcd, err path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
            {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    if (!ThumbnailUtils::ScaleThumbnailEx(data)) {
        MEDIA_ERR_LOG("Fail to scale from LCD to THM, err path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }

    if (!DoCreateThumbnail(opts, data)) {
        MEDIA_ERR_LOG("Fail to create thumbnail, err path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
            {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    return true;
}

std::string GetAvailableThumbnailSuffix(ThumbnailData &data)
{
    // Check whether the thumbnail data exist, firstly thumb then lcd, and return the corresponding suffix.
    // When there is no thumbnail data, return empty string.
    if (access(GetThumbnailPath(data.path, THUMBNAIL_THUMB_SUFFIX).c_str(), F_OK) == 0) {
        return THUMBNAIL_THUMB_SUFFIX;
    }
    if (access(GetThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX).c_str(), F_OK) == 0) {
        return THUMBNAIL_LCD_SUFFIX;
    }
    return "";
}

bool IThumbnailHelper::DoCreateAstc(ThumbRdbOpt &opts, ThumbnailData &data)
{
    MEDIA_INFO_LOG("Start DoCreateAstc, id: %{public}s, path: %{public}s", data.id.c_str(), data.path.c_str());
    data.useThumbAsSource = true;
    data.isLoadingFromThumbToLcd = true;
    if (!TryLoadSource(opts, data)) {
        MEDIA_ERR_LOG("DoCreateAstc failed, try to load exist thumbnail failed, id: %{public}s", data.id.c_str());
        return false;
    }

    if (!GenThumbnail(opts, data, ThumbnailType::THUMB_ASTC)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN}, {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::MTH_ASTC) || !GenThumbnail(opts, data, ThumbnailType::YEAR_ASTC)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN}, {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }

    data.fileUri = MediaFileUtils::GetUriByExtrConditions(PhotoColumn::DEFAULT_PHOTO_URI + "/", data.id,
        MediaFileUtils::GetExtraUri(data.displayName, data.path));
    if (!UpdateThumbnailState(opts, data)) {
        MEDIA_ERR_LOG("UpdateThumbnailState fail");
        return false;
    }
    return true;
}

bool IThumbnailHelper::IsPureCloudImage(ThumbRdbOpt &opts)
{
    vector<string> columns = {
        MEDIA_DATA_DB_ID,
        PhotoColumn::PHOTO_POSITION
    };
    if (opts.row.empty() || opts.table.empty()) {
        MEDIA_ERR_LOG("IsPureCloudImage opts.row is empty");
        return false;
    }
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + opts.row;
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.SetWhereClause(strQueryCondition);
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("IsPureCloudImage opts.store is nullptr");
        return false;
    }
    auto resultSet = opts.store->QueryByStep(rdbPredicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("IsPureCloudImage result set is null");
        return false;
    }
    auto ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("IsPureCloudImage go to first row failed");
        return false;
    }
    int photoPosition = GetInt32Val(PhotoColumn::PHOTO_POSITION, resultSet);

    // if current image is a pure cloud image, it's photo position column in database will be 2
    return photoPosition == 2;
}
} // namespace Media
} // namespace OHOS