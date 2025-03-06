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

import { AnalysisType } from "./media_library_enum.ets";

type MemberType = number | string | boolean;

declare namespace image {
    export interface PixelMap {}
    export interface Size {
        height: number;
        width: number;
    }
}

class SizeImpl implements image.Size {
    height: number = 1;
    width: number = 1;
}

export class PhotoAssetHandle {
    static { loadLibrary("photo_access_helper_ani"); }
    private  nativePhotoAsset: long = 0;

    constructor(context: long) {
        if (this.nativePhotoAsset == 0) {
            this.nativePhotoAsset = context;
        }
    }

    native static create(): PhotoAssetHandle;
    native set(member: string, value: string): void;
    native get(member: string): MemberType;
    native commitModify(): void;
    native open(mode: string): number;
    native close(fd: number): void;
    native getThumbnail(size?: image.Size): image.PixelMap;
    native setFavorite(favoriteState: boolean): void;
    native setHidden(hiddenState: boolean): void;
    native setUserComment(userComment: string): void;
    native getAnalysisData(analysisType: AnalysisType): string;
}
