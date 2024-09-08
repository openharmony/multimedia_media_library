/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_MOVING_PHOTO_PROCESSOR_H
#define OHOS_MEDIALIBRARY_MOVING_PHOTO_PROCESSOR_H

#include "abs_shared_result_set.h"
#include "medialibrary_async_worker.h"
#include "userfile_manager_types.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class MovingPhotoProcessor {
public:
    EXPORT static void StartProcess();
    EXPORT static void StopProcess();

private:
    typedef struct {
        int32_t fileId;
        int32_t subtype;
        int32_t effectMode;
        int64_t size;
        std::string path;
    } MovingPhotoData;

    typedef struct {
        std::vector<MovingPhotoData> movingPhotos;
    } MovingPhotoDataList;

    class CompatMovingPhotoData : public AsyncTaskData {
    public:
        CompatMovingPhotoData(MovingPhotoDataList dataList) : dataList_(dataList) {};
        ~CompatMovingPhotoData() override = default;

        MovingPhotoDataList dataList_;
    };

    static std::shared_ptr<NativeRdb::ResultSet> QueryMovingPhoto();
    static void ParseMovingPhotoData(std::shared_ptr<NativeRdb::ResultSet>& resultSet, MovingPhotoDataList& dataList);
    static int32_t AddTask(const MovingPhotoDataList& dataList);
    static void CompatMovingPhotoExecutor(AsyncTaskData* data);
    static int32_t GetUpdatedMovingPhotoData(const MovingPhotoData& currentData, MovingPhotoData& newData);
    static void UpdateMovingPhotoData(const MovingPhotoData& movingPhotoData);

    static bool isProcessing_;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_MOVING_PHOTO_PROCESSOR_H