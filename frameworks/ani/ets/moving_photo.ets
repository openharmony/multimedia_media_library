/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import { Context } from "./media_library_common.ets";
import { ResourceType } from "./media_library_enum.ets";

export class MovingPhotoHandle {
    static { loadLibrary("photo_access_helper_ani"); }
    private nativeMovingPhoto: long = 0;

    constructor(context: long) {
        if (this.nativeMovingPhoto == 0) {
            this.nativeMovingPhoto = context;
        }
    }

    requestContent(imageFileUri: string, videoFileUri: string): void {
        this.requestContent1(imageFileUri, videoFileUri);
    }
    requestContent(resourceType: ResourceType, fileUri: string): void {
        this.requestContent2(resourceType, fileUri);
    }
    requestContent(resourceType: ResourceType): void {
        this.requestContent3(resourceType);
    }

    native static create(context: Context): MovingPhotoHandle;
    native requestContent1(imageFileUri: string, videoFileUri: string): void;
    native requestContent2(resourceType: ResourceType, fileUri: string): void;
    native requestContent3(resourceType: ResourceType): void;
    native getUri(): string;
}

function getMovingPhoto(context: Context): MovingPhotoHandle {
    let movingPhoto = MovingPhotoHandle.create(context);
    return movingPhoto;
}
