/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "ptp_album_handles.h"

#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "rdb_class_utils.h"

namespace OHOS {
namespace Media {
using namespace std;
std::shared_ptr<PtpAlbumHandles> PtpAlbumHandles::instance_ = nullptr;
std::mutex PtpAlbumHandles::mutex_;

std::shared_ptr<PtpAlbumHandles> PtpAlbumHandles::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<PtpAlbumHandles>();
        }
    }
    return instance_;
}

PtpAlbumHandles::~PtpAlbumHandles()
{
    std::lock_guard<std::mutex> lock(mutex_);
    dataHandles_.clear();
}

void PtpAlbumHandles::AddHandle(int32_t value)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = std::find(dataHandles_.begin(), dataHandles_.end(), value);
    if (iter == dataHandles_.end()) {
        dataHandles_.push_back(value);
    }
}

void PtpAlbumHandles::RemoveHandle(int32_t value)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = std::find(dataHandles_.begin(), dataHandles_.end(), value);
    if (iter != dataHandles_.end()) {
        dataHandles_.erase(iter);
    }
}

void PtpAlbumHandles::AddAlbumHandles(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    dataHandles_.clear();
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t id = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        dataHandles_.push_back(id);
    }
    resultSet->GoToFirstRow();
}

bool PtpAlbumHandles::FindHandle(int32_t value)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = std::find(dataHandles_.begin(), dataHandles_.end(), value);
    return iter != dataHandles_.end();
}

int32_t PtpAlbumHandles::ChangeHandle(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return E_ERR;
    }
    std::vector<int32_t> data;
    do {
        int32_t id = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
        data.push_back(id);
    } while (!resultSet->GoToNextRow());

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto value : dataHandles_) {
        auto iter = std::find(data.begin(), data.end(), value);
        if (iter == data.end()) {
            return value;
        }
    }
    MEDIA_ERR_LOG("no data handle to remove");
    return E_ERR;
}
} // namespace Media
} // namespace OHOS