/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "fetch_result.h"
#include "media_log.h"

using namespace std;

namespace {
    const int ARG1 = 0;
    const int ARG2 = 1;
    const int ARG3 = 2;
}

namespace OHOS {
namespace Media {
FetchResult::FetchResult(const shared_ptr<OHOS::NativeRdb::AbsSharedResultSet>& resultset)
{
    if (resultset != nullptr) {
        resultset->GetRowCount(count_);
    }
    isContain_ = count_ > 0;
    isClosed_ = false;
    resultset_ = resultset;
}

// empty constructor napi
FetchResult::FetchResult() {}

FetchResult::~FetchResult() {}

void FetchResult::Close()
{
    isClosed_ = true;
}

bool FetchResult::IsContain()
{
    return isContain_;
}

int32_t FetchResult::GetCount()
{
    return count_;
}

bool FetchResult::IsClosed()
{
    return isClosed_;
}

unique_ptr<FileAsset> FetchResult::GetObjectAtPosition(int32_t index)
{
    if ((index < 0) || (index > (count_ - 1)) || (resultset_ == nullptr)) {
        MEDIA_ERR_LOG("index not proper or rs is null");
        return nullptr;
    }

    if (resultset_->GoToRow(index) != 0) {
        MEDIA_ERR_LOG("failed to go to row at index pos");
        return nullptr;
    }

    return GetObject();
}

unique_ptr<FileAsset> FetchResult::GetFirstObject()
{
    if ((resultset_ == nullptr) || (resultset_->GoToFirstRow() != 0)) {
        MEDIA_ERR_LOG("resultset is null|first row failed");
        return nullptr;
    }

    return GetObject();
}

unique_ptr<FileAsset> FetchResult::GetNextObject()
{
    if ((resultset_ == nullptr) || (resultset_->GoToNextRow() != 0)) {
        MEDIA_ERR_LOG("resultset is null|go to next row failed");
        return nullptr;
    }

    return GetObject();
}

unique_ptr<FileAsset> FetchResult::GetLastObject()
{
    if ((resultset_ == nullptr) || (resultset_->GoToLastRow() != 0)) {
        MEDIA_ERR_LOG("resultset is null|go to last row failed");
        return nullptr;
    }

    return GetObject();
}

bool FetchResult::IsAtLastRow()
{
    if (resultset_ == nullptr) {
        MEDIA_ERR_LOG("resultset null");
        return false;
    }

    bool retVal = false;
    resultset_->IsAtLastRow(retVal);
    return retVal;
}

variant<int32_t, int64_t, string> ReturnDefaultOnError(string errMsg, ResultSetDataType dataType)
{
    MEDIA_ERR_LOG("%{public}s", errMsg.c_str());
    if ((dataType) == TYPE_STRING)
        return "";
    else
        return 0;
}

variant<int32_t, int64_t, string> FetchResult::GetRowValFromColumnn(string columnName, ResultSetDataType dataType)
{
    int index;
    variant<int32_t, int64_t, string> cellValue;
    int integerVal = 0;
    string stringVal = "";
    int64_t longVal = 0;
    int status;

    if (resultset_ == nullptr) {
        ReturnDefaultOnError("Resultset is null", dataType);
    }

    status = resultset_->GetColumnIndex(columnName, index);
    if (status != NativeRdb::E_OK) {
        ReturnDefaultOnError("failed to obtain the index", dataType);
    }

    switch (dataType) {
        case TYPE_STRING:
            status = resultset_->GetString(index, stringVal);
            if (status != NativeRdb::E_OK) {
                ReturnDefaultOnError("failed to obtain string value from resultse", dataType);
            }
            cellValue = stringVal;
            break;
        case TYPE_INT32:
            status = resultset_->GetInt(index, integerVal);
            if (status != NativeRdb::E_OK) {
                ReturnDefaultOnError("failed to obtain int value from resultset", dataType);
            }
            cellValue = integerVal;
            break;
        case TYPE_INT64:
            status = resultset_->GetLong(index, longVal);
            if (status != NativeRdb::E_OK) {
                ReturnDefaultOnError("failed to obtain long value from resultset", dataType);
            }

            cellValue = longVal;
            break;
        default:
            break;
    }

    return cellValue;
}

unique_ptr<FileAsset> FetchResult::GetObject()
{
    unique_ptr<FileAsset> fileAsset = make_unique<FileAsset>();

    fileAsset->SetId(get<ARG1>(GetRowValFromColumnn(MEDIA_DATA_DB_ID, TYPE_INT32)));

    fileAsset->SetUri(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_URI, TYPE_STRING)));

    fileAsset->SetMimeType(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_MIME_TYPE, TYPE_STRING)));

    fileAsset->SetMediaType(static_cast<Media::MediaType>(get<ARG1>(
        GetRowValFromColumnn(MEDIA_DATA_DB_MEDIA_TYPE, TYPE_INT32))));

    fileAsset->SetPath(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_FILE_PATH, TYPE_STRING)));

    fileAsset->SetRelativePath(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_RELATIVE_PATH, TYPE_STRING)));

    fileAsset->SetDisplayName(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_NAME, TYPE_STRING)));

    fileAsset->SetSize(get<ARG2>(GetRowValFromColumnn(MEDIA_DATA_DB_SIZE, TYPE_INT64)));

    fileAsset->SetDateAdded(get<ARG2>(GetRowValFromColumnn(MEDIA_DATA_DB_DATE_ADDED, TYPE_INT64)));

    fileAsset->SetDateModified(get<ARG2>(GetRowValFromColumnn(MEDIA_DATA_DB_DATE_MODIFIED, TYPE_INT64)));

    fileAsset->SetTitle(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_TITLE, TYPE_STRING)));

    fileAsset->SetArtist(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_ARTIST, TYPE_STRING)));

    fileAsset->SetAlbum(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_ALBUM, TYPE_STRING)));

    fileAsset->SetWidth(get<ARG1>(GetRowValFromColumnn(MEDIA_DATA_DB_WIDTH, TYPE_INT32)));

    fileAsset->SetHeight(get<ARG1>(GetRowValFromColumnn(MEDIA_DATA_DB_HEIGHT, TYPE_INT32)));

    fileAsset->SetDuration(get<ARG1>(GetRowValFromColumnn(MEDIA_DATA_DB_DURATION, TYPE_INT32)));

    fileAsset->SetOrientation(get<ARG1>(GetRowValFromColumnn(MEDIA_DATA_DB_ORIENTATION, TYPE_INT32)));

    fileAsset->SetAlbumId(get<ARG1>(GetRowValFromColumnn(MEDIA_DATA_DB_PARENT_ID, TYPE_INT32)));

    fileAsset->SetAlbumName(get<ARG3>(GetRowValFromColumnn(MEDIA_DATA_DB_ALBUM_NAME, TYPE_STRING)));

    return fileAsset;
}
}  // namespace Media
}  // namespace OHOS
