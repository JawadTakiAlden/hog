<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\File;

class Question extends Model
{
    use HasFactory;
    protected $guarded = ['id'];

    public function choices(){
        return $this->hasMany(Choice::class);
    }


//    protected static function boot()
//    {
//        parent::boot();
//        static::deleting(function ($question) {
//            if ($question->image){
//                $imagePath = public_path($question->image);
//                if (File::exists($imagePath)) {
//                    File::delete($imagePath);
//                }
//            }
//            if ($question->clarification_image){
//                $imagePath = public_path($question->clarification_image);
//                if (File::exists($imagePath)) {
//                    File::delete($imagePath);
//                }
//            }
//        });
//        static::updated(function ($question) {
//            if ($question->image){
//                if ($question->isDirty('image')) {
//                    $oldImagePath = public_path($question->getOriginal('image'));
//                    if (File::exists($oldImagePath)) {
//                        File::delete($oldImagePath);
//                    }
//                }
//            }
//            if ($question->clarification_image){
//                if ($question->isDirty('clarification_image')) {
//                    $oldImagePath = public_path($question->getOriginal('clarification_image'));
//                    if (File::exists($oldImagePath)) {
//                        File::delete($oldImagePath);
//                    }
//                }
//            }
//        });
//    }

    public function setImageAttribute ($image){
        $newImageName = uniqid() . '_' . 'image' . '.' . $image->extension();
        $image->move(public_path('question_images') , $newImageName);
        return $this->attributes['image'] =  '/'.'question_images'.'/' . $newImageName;
    }

    public function setClarificationImageAttribute($clarification_image){
        $newImageName = uniqid() . '_' . 'image' . '.' . $clarification_image->extension();
        $clarification_image->move(public_path('clarification_images') , $newImageName);
        return $this->attributes['clarification_image'] =  '/'.'clarification_images'.'/' . $newImageName;
    }
}
