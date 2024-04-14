<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AccountInrolment extends Model
{
    use HasFactory;
    protected $guarded = ['id'];


    public function course(){
        return $this->belongsTo(Course::class);
    }

    public function user(){
        return $this->belongsTo(User::class);
    }

    public function chapters(){
        return $this->hasMany(Chapter::class);
    }

    public function activationCode(){
        return $this->belongsTo(ActivationCode::class);
    }
}
