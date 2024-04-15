<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\File;

class News extends Model
{
    use HasFactory;
    protected $guarded = ['id'];

    public function setImageAttribute ($image){
        if (!$image){
            return $this->attributes['image'] = fake()->imageUrl;
        }
        $newImageName = uniqid() . '_' . 'image' . '.' . $image->extension();
        $image->move(public_path('news_images') , $newImageName);
        return $this->attributes['image'] =  '/'.'news_images'.'/' . $newImageName;
    }

//    protected static function boot()
//    {
//        parent::boot();
//        static::deleting(function ($news) {
//            $imagePath = public_path($news->image);
//            if (File::exists($imagePath)) {
//                File::delete($imagePath);
//            }
//        });
//        static::updated(function ($news) {
//            if ($news->image){
//                if ($news->isDirty('image')) {
//                    $oldImagePath = public_path($news->getOriginal('image'));
//                    if (File::exists($oldImagePath)) {
//                        File::delete($oldImagePath);
//                    }
//                }
//            }
//        });
//    }
}
