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

#define MLOG_TAG "PictureManagerThread"

#include "picture_manager_thread.h"
#include "file_utils.h"
#include "media_log.h"
#include "parameter.h"
#include "parameters.h"

using namespace std;
namespace OHOS {
namespace Media {
unique_ptr<PictureManagerThread> PictureManagerThread::instance_ = nullptr;
mutex PictureManagerThread::mutex_;
PictureManagerThread* PictureManagerThread::GetInstance()
{
    if (instance_ == nullptr) {
        lock_guard<mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = make_unique<PictureManagerThread>();
        }
    }
    return instance_.get();
}
PictureManagerThread::PictureManagerThread()
    : thread_(nullptr),
      pauseFlag_(false),
      stopFlag_(false),
      state_(State::STOPPED)
{
}

PictureManagerThread::~PictureManagerThread()
{
    pictureDataOperations_ = nullptr;
    Stop();
}

State PictureManagerThread::State() const
{
    return state_;
}

void PictureManagerThread::Start()
{
    unique_lock<mutex> locker(runningMutex_);
    if (pictureDataOperations_ == nullptr) {
        pictureDataOperations_ = new PictureDataOperations();
    }
    if (pauseFlag_) {
        Stop();
    }
    if (thread_ == nullptr) {
        thread_ = std::make_unique<std::thread>(&PictureManagerThread::Run, this);
        pauseFlag_ = false;
        stopFlag_ = false;
        state_ = State::RUNNING;
    }
}

void PictureManagerThread::Stop()
{
    MEDIA_INFO_LOG("enter ");
    if (thread_ != nullptr) {
        pauseFlag_ = false;
        stopFlag_ = true;
        condition_.notify_all();  // Notify one waiting thread, if there is one.
        if (thread_->joinable()) {
            thread_->join(); // wait for thread finished
        }
        thread_ = nullptr;
        state_ = State::STOPPED;
    }
}

void PictureManagerThread::Pause()
{
    MEDIA_INFO_LOG("enter ");
    if (thread_ != nullptr) {
        pauseFlag_ = true;
        state_ = State::PAUSED;
    }
}

void PictureManagerThread::Resume()
{
    MEDIA_INFO_LOG("enter ");
    if (thread_ != nullptr) {
        pauseFlag_ = false;
        condition_.notify_all();
        state_ = State::RUNNING;
    }
}

void PictureManagerThread::Run()
{
    MEDIA_INFO_LOG("enter thread run:");
    string name("PictureManagerThread");
    pthread_setname_np(pthread_self(), name.c_str());
    while (!stopFlag_) {
        if (pictureDataOperations_ == nullptr) {
            pictureDataOperations_ = new PictureDataOperations();
        }
        pictureDataOperations_->CleanDateForPeriodical();
        unique_lock<mutex> locker(threadMutex_);
        condition_.wait_for(locker, std::chrono::seconds(1)); // 实际1S扫描一次
        int32_t taskSize = pictureDataOperations_->GetPendingTaskSize();
        if (lastPendingTaskSize_ != 0 && taskSize == 0) {
            pauseFlag_ = true;
            return;
        }
        lastPendingTaskSize_ = taskSize;
    }
}

void PictureManagerThread::InsertPictureData(const std::string& imageId, sptr<PicturePair>& PicturePair,
    PictureType pictureType)
{
    Start();
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("InsertPictureData failed, pictureDataOperations_ is null");
        return;
    }
    pictureDataOperations_->InsertPictureData(imageId, PicturePair, pictureType);
}

void PictureManagerThread::DeleteDataWithImageId(const std::string& imageId, PictureType pictureType)
{
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("InsertPictureData failed, pictureDataOperations_ is null");
        return;
    }
    pictureDataOperations_->DeleteDataWithImageId(imageId, pictureType);
}

std::shared_ptr<Media::Picture> PictureManagerThread::GetDataWithImageId(const std::string& imageId,
    bool &isHighQualityPicture, bool isCleanImmediately)
{
    MEDIA_DEBUG_LOG("enter ");
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("GetDataWithImageId failed, pictureDataOperations_ is null");
        return nullptr;
    }
    return pictureDataOperations_->GetDataWithImageId(imageId, isHighQualityPicture, isCleanImmediately);
}

void PictureManagerThread::SavePictureWithImageId(const std::string& imageId)
{
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("SavePictureWithImageId failed, pictureDataOperations_ is null");
        return;
    }
    return pictureDataOperations_->SavePictureWithImageId(imageId);
}

int32_t PictureManagerThread::AddSavePictureTask(sptr<PicturePair>& picturePair)
{
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("AddSavePictureTask failed, pictureDataOperations_ is null");
        return 0;
    }
    pictureDataOperations_->AddSavePictureTask(picturePair);
    return 0;
}

int32_t PictureManagerThread::GetPendingTaskSize()
{
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("GetPendingTaskSize failed, pictureDataOperations_ is null");
        return 0;
    }
    return pictureDataOperations_->GetPendingTaskSize();
}

bool PictureManagerThread::IsExsitDataForPictureType(PictureType pictureType)
{
    MEDIA_INFO_LOG("enter ");
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("IsExsitDataForPictureType failed, pictureDataOperations_ is null");
        return false;
    }
    return pictureDataOperations_->IsExsitDataForPictureType(pictureType);
}

bool PictureManagerThread::IsExsitPictureByImageId(const std::string& imageId)
{
    MEDIA_INFO_LOG("enter ");
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("IsExsitDataForPictureType failed, pictureDataOperations_ is null");
        return false;
    }
    enum PictureType pictureType;
    for (pictureType = HIGH_QUALITY_PICTURE; pictureType >= LOW_QUALITY_PICTURE;
        pictureType = (PictureType)(pictureType - 1)) {
        if (pictureDataOperations_->IsExsitDataForPictureType(imageId, pictureType)) {
            return true;
        }
    }
    return false;
}

// 落盘低质量图，包括低质量裸图/低质量
void PictureManagerThread::SaveLowQualityPicture(const std::string& imageId)
{
    MEDIA_INFO_LOG("enter ");
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("SaveLowQualityPicture failed, pictureDataOperations_ is null");
        return;
    }
    pictureDataOperations_->SaveLowQualityPicture(imageId);
}

void PictureManagerThread::FinishAccessingPicture(const std::string& imageId)
{
    MEDIA_INFO_LOG("enter ");
    if (pictureDataOperations_ == nullptr) {
        MEDIA_ERR_LOG("FinishAccessingPicture failed, pictureDataOperations_ is null");
        return;
    }
    enum PictureType pictureType;
    for (pictureType = HIGH_QUALITY_PICTURE; pictureType >= LOW_QUALITY_PICTURE;
        pictureType = (PictureType)(pictureType - 1)) {
        pictureDataOperations_->FinishAccessingPicture(imageId, pictureType);
    }
    MEDIA_INFO_LOG("FinishAccessingPicture end: %{public}s", imageId.c_str());
}
} // namespace Media
} // namespace OHOS